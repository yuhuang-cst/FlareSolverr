"""Camoufox browser engine for request.download command.

Uses Camoufox (anti-fingerprint Firefox) + playwright-captcha (ClickSolver)
to solve CAPTCHAs and download files. Runs in headless mode.

Requires: pip install camoufox playwright-captcha
          camoufox fetch
"""

import base64
import logging
import time
from urllib.parse import urlparse

from camoufox import AsyncCamoufox
from playwright.async_api import Browser, BrowserContext, Page
from playwright_captcha import ClickSolver, FrameworkType, CaptchaType

logger = logging.getLogger("uvicorn.error")

# Challenge titles to detect
CHALLENGE_TITLES = [
    'Just a moment...',
    'DDoS-Guard',
]

# Selectors indicating an active challenge
CHALLENGE_SELECTORS = [
    '#cf-challenge-running', '.ray_id', '.attack-box',
    '#cf-please-wait', '#challenge-spinner', '#trk_jschal_js',
    '#turnstile-wrapper', '.lds-ring',
]


async def camoufox_download(url: str, max_timeout: int = 60000,
                            proxy: dict = None) -> dict:
    """Download file using Camoufox + playwright-captcha.

    Args:
        url: Target PDF URL.
        max_timeout: Max timeout in milliseconds.
        proxy: Optional proxy config {server, username, password}.

    Returns:
        dict: {status, message, url, cookies, userAgent, fileBase64}
    """
    timeout_sec = max_timeout / 1000
    start_time = time.time()

    proxy_config = None
    if proxy and 'url' in proxy:
        parsed = urlparse(proxy['url'])
        proxy_config = {
            "server": proxy['url'],
            "username": proxy.get('username'),
            "password": proxy.get('password'),
        }

    try:
        from playwright_captcha.utils.camoufox_add_init_script.add_init_script import (
            get_addon_path,
        )
        addon_path = get_addon_path()
    except Exception:
        addon_path = None

    addons = [addon_path] if addon_path else []

    async with AsyncCamoufox(
        main_world_eval=True,
        addons=addons,
        geoip=True,
        proxy=proxy_config,
        locale="en-US",
        headless=True,
        humanize=True,
        i_know_what_im_doing=True,
        config={"forceScopeAccess": True},
        disable_coop=True,
    ) as browser_raw:
        browser = browser_raw
        context = await browser.new_context()
        page = await context.new_page()

        async with ClickSolver(
            framework=FrameworkType.CAMOUFOX,
            page=page,
            max_attempts=3,
            attempt_delay=1,
        ) as solver:
            return await _download_with_page(
                page, context, solver, url, timeout_sec, start_time)


async def _download_with_page(
        page: Page, context: BrowserContext, solver: ClickSolver,
        url: str, timeout_sec: float, start_time: float) -> dict:
    """Core download logic using Playwright page."""

    # Step 1: Navigate to URL
    logger.info(f"[Camoufox] Navigating to {url[:80]}...")
    try:
        await page.goto(url, timeout=min(timeout_sec, 30) * 1000,
                        wait_until='domcontentloaded')
    except Exception as e:
        logger.debug(f"[Camoufox] Navigation error (may be expected): {str(e)[:80]}")

    # Step 2: Solve Cloudflare challenge if detected
    title = await page.title()
    challenge_found = any(t.lower() == title.lower() for t in CHALLENGE_TITLES)

    if challenge_found:
        logger.info(f"[Camoufox] Challenge detected: {title}")
        try:
            await solver.solve_captcha(
                captcha_container=page,
                captcha_type=CaptchaType.CLOUDFLARE_INTERSTITIAL,
                wait_checkbox_attempts=3,
                wait_checkbox_delay=0.5,
            )
            logger.info("[Camoufox] Challenge solved!")
        except Exception as e:
            logger.warning(f"[Camoufox] ClickSolver failed: {e}, waiting for JS...")
            # Fallback: wait for JS challenge to complete
            for _ in range(15):
                title = await page.title()
                if not any(t.lower() == title.lower() for t in CHALLENGE_TITLES):
                    break
                await page.wait_for_timeout(1000)

    # Step 2.5: Wait for non-Cloudflare challenges (AWS WAF, etc.)
    _wait_start = time.time()
    while time.time() - _wait_start < 15:
        try:
            content = await page.content()
        except Exception:
            content = ''

        has_waf = 'awsWafCookieDomainList' in content
        has_challenge = ('challenge' in content.lower()[:2000]
                         and len(content) < 5000
                         and '<form' not in content.lower()[:2000])

        if has_waf or has_challenge:
            if time.time() - _wait_start < 1:
                logger.info(f"[Camoufox] JS challenge detected (WAF={has_waf})")
            await page.wait_for_timeout(1000)
        else:
            break

    # Step 3: Determine fetch URL (handle CDN redirects and native downloads)
    current_url = page.url
    target_origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    current_origin = f"{urlparse(current_url).scheme}://{urlparse(current_url).netloc}"

    is_internal = current_url.startswith(('chrome://', 'about:', 'data:'))

    if is_internal:
        logger.info(f"[Camoufox] Native download detected, navigating to {target_origin}")
        await page.goto(target_origin, wait_until='domcontentloaded')
        # Wait for possible challenge on base URL
        title = await page.title()
        if any(t.lower() == title.lower() for t in CHALLENGE_TITLES):
            try:
                await solver.solve_captcha(
                    captcha_container=page,
                    captcha_type=CaptchaType.CLOUDFLARE_INTERSTITIAL,
                )
            except Exception:
                for _ in range(15):
                    title = await page.title()
                    if not any(t.lower() == title.lower() for t in CHALLENGE_TITLES):
                        break
                    await page.wait_for_timeout(1000)
        fetch_url = url
    elif current_origin != target_origin:
        fetch_url = current_url
        logger.info(f"[Camoufox] Redirected to {current_origin}, will fetch: {fetch_url[:80]}")
    else:
        fetch_url = url

    # Step 4: JS fetch the file
    logger.info(f"[Camoufox] Downloading via JS fetch...")
    try:
        js_result = await page.evaluate("""
            async (url) => {
                try {
                    const r = await fetch(url);
                    if (!r.ok) return {error: 'HTTP ' + r.status + ' ' + r.statusText};
                    const blob = await r.blob();
                    return new Promise((resolve) => {
                        const reader = new FileReader();
                        reader.onloadend = () => resolve({
                            data: reader.result.split(',')[1],
                            size: blob.size,
                            type: blob.type
                        });
                        reader.onerror = () => resolve({error: 'FileReader error'});
                        reader.readAsDataURL(blob);
                    });
                } catch (e) {
                    return {error: e.toString()};
                }
            }
        """, fetch_url)
    except Exception as e:
        raise Exception(f"[Camoufox] JS fetch failed: {e}")

    if not isinstance(js_result, dict) or 'error' in js_result:
        error = js_result.get('error', 'Unknown') if isinstance(js_result, dict) else str(js_result)
        raise Exception(f"[Camoufox] JS fetch error: {error}")

    file_base64 = js_result.get('data')
    if not file_base64:
        raise Exception("[Camoufox] JS fetch returned no data")

    elapsed = time.time() - start_time
    logger.info(f"[Camoufox] Download complete: {js_result.get('size', '?')} bytes, "
                f"type: {js_result.get('type', '?')}, {elapsed:.1f}s")

    # Build response
    cookies = await context.cookies()
    user_agent = await page.evaluate("navigator.userAgent")

    return {
        'status': 'ok',
        'message': 'File downloaded successfully',
        'url': current_url,
        'cookies': cookies,
        'userAgent': user_agent,
        'fileBase64': file_base64,
    }

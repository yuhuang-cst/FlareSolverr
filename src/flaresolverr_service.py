import base64
import logging
import platform
import sys
import time
from datetime import timedelta
from html import escape
from urllib.parse import unquote, quote, urlparse

from func_timeout import FunctionTimedOut, func_timeout
from selenium.common import TimeoutException
from selenium.webdriver.chrome.webdriver import WebDriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.expected_conditions import (
    presence_of_element_located, staleness_of, title_is)
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.wait import WebDriverWait

import utils
from dtos import (STATUS_ERROR, STATUS_OK, ChallengeResolutionResultT,
                  ChallengeResolutionT, HealthResponse, IndexResponse,
                  V1RequestBase, V1ResponseBase)
from sessions import SessionsStorage

ACCESS_DENIED_TITLES = [
    # Cloudflare
    'Access denied',
    # Cloudflare http://bitturk.net/ Firefox
    'Attention Required! | Cloudflare'
]
ACCESS_DENIED_SELECTORS = [
    # Cloudflare
    'div.cf-error-title span.cf-code-label span',
    # Cloudflare http://bitturk.net/ Firefox
    '#cf-error-details div.cf-error-overview h1'
]
CHALLENGE_TITLES = [
    # Cloudflare
    'Just a moment...',
    # DDoS-GUARD
    'DDoS-Guard'
]
CHALLENGE_SELECTORS = [
    # Cloudflare
    '#cf-challenge-running', '.ray_id', '.attack-box', '#cf-please-wait', '#challenge-spinner', '#trk_jschal_js', '#turnstile-wrapper', '.lds-ring',
    # Custom CloudFlare for EbookParadijs, Film-Paleis, MuziekFabriek and Puur-Hollands
    'td.info #js_info',
    # Fairlane / pararius.com
    'div.vc div.text-box h2'
]

TURNSTILE_SELECTORS = [
    "input[name='cf-turnstile-response']"
]

SHORT_TIMEOUT = 1
SESSIONS_STORAGE = SessionsStorage()


def test_browser_installation():
    logging.info("Testing web browser installation...")
    logging.info("Platform: " + platform.platform())

    chrome_exe_path = utils.get_chrome_exe_path()
    if chrome_exe_path is None:
        logging.error("Chrome / Chromium web browser not installed!")
        sys.exit(1)
    else:
        logging.info("Chrome / Chromium path: " + chrome_exe_path)

    chrome_major_version = utils.get_chrome_major_version()
    if chrome_major_version == '':
        logging.error("Chrome / Chromium version not detected!")
        sys.exit(1)
    else:
        logging.info("Chrome / Chromium major version: " + chrome_major_version)

    logging.info("Launching web browser...")
    user_agent = utils.get_user_agent()
    logging.info("FlareSolverr User-Agent: " + user_agent)
    logging.info("Test successful!")


def index_endpoint() -> IndexResponse:
    res = IndexResponse({})
    res.msg = "FlareSolverr is ready!"
    res.version = utils.get_flaresolverr_version()
    res.userAgent = utils.get_user_agent()
    return res


def health_endpoint() -> HealthResponse:
    res = HealthResponse({})
    res.status = STATUS_OK
    return res


def controller_v1_endpoint(req: V1RequestBase) -> V1ResponseBase:
    start_ts = int(time.time() * 1000)
    logging.info(f"Incoming request => POST /v1 body: {utils.object_to_dict(req)}")
    res: V1ResponseBase
    try:
        res = _controller_v1_handler(req)
    except Exception as e:
        res = V1ResponseBase({})
        res.__error_500__ = True
        res.status = STATUS_ERROR
        res.message = "Error: " + str(e)
        logging.error(res.message)

    res.startTimestamp = start_ts
    res.endTimestamp = int(time.time() * 1000)
    res.version = utils.get_flaresolverr_version()
    logging.debug(f"Response => POST /v1 body: {utils.object_to_dict(res)}")
    logging.info(f"Response in {(res.endTimestamp - res.startTimestamp) / 1000} s")
    return res


def _controller_v1_handler(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.cmd is None:
        raise Exception("Request parameter 'cmd' is mandatory.")
    if req.headers is not None:
        logging.warning("Request parameter 'headers' was removed in FlareSolverr v2.")
    if req.userAgent is not None:
        logging.warning("Request parameter 'userAgent' was removed in FlareSolverr v2.")

    # set default values
    if req.maxTimeout is None or int(req.maxTimeout) < 1:
        req.maxTimeout = 60000

    # execute the command
    res: V1ResponseBase
    if req.cmd == 'sessions.create':
        res = _cmd_sessions_create(req)
    elif req.cmd == 'sessions.list':
        res = _cmd_sessions_list(req)
    elif req.cmd == 'sessions.destroy':
        res = _cmd_sessions_destroy(req)
    elif req.cmd == 'request.get':
        res = _cmd_request_get(req)
    elif req.cmd == 'request.download':
        res = _cmd_request_download(req)
    elif req.cmd == 'request.post':
        res = _cmd_request_post(req)
    else:
        raise Exception(f"Request parameter 'cmd' = '{req.cmd}' is invalid.")

    return res


def _cmd_request_get(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.url is None:
        raise Exception("Request parameter 'url' is mandatory in 'request.get' command.")
    if req.postData is not None:
        raise Exception("Cannot use 'postBody' when sending a GET request.")
    if req.returnRawHtml is not None:
        logging.warning("Request parameter 'returnRawHtml' was removed in FlareSolverr v2.")
    if req.download is not None:
        logging.warning("Request parameter 'download' was removed in FlareSolverr v2.")

    challenge_res = _resolve_challenge(req, 'GET')
    res = V1ResponseBase({})
    res.status = challenge_res.status
    res.message = challenge_res.message
    res.solution = challenge_res.result
    return res


def _cmd_request_download(req: V1RequestBase) -> V1ResponseBase:
    """Download a file (e.g. PDF) after solving the Cloudflare challenge.

    Uses the same browser session that passed Cloudflare to navigate to the
    file URL, then intercepts the response body via CDP Fetch API and returns
    it as base64 in solution.fileBase64.
    """
    if req.url is None:
        raise Exception("Request parameter 'url' is mandatory in 'request.download' command.")

    timeout = int(req.maxTimeout) / 1000
    driver = None
    try:
        if req.session:
            session_id = req.session
            ttl = timedelta(minutes=req.session_ttl_minutes) if req.session_ttl_minutes else None
            session, fresh = SESSIONS_STORAGE.get(session_id, ttl)
            driver = session.driver
        else:
            driver = utils.get_webdriver(req.proxy)

        return func_timeout(timeout, _download_file_logic, (req, driver))
    except FunctionTimedOut:
        raise Exception(f'Error downloading file. Timeout after {timeout} seconds.')
    except Exception as e:
        raise Exception('Error downloading file. ' + str(e).replace('\n', '\\n'))
    finally:
        if not req.session and driver is not None:
            if utils.PLATFORM_VERSION == "nt":
                driver.close()
            driver.quit()


def _download_file_logic(req: V1RequestBase, driver: WebDriver) -> V1ResponseBase:
    """Navigate to URL, solve challenge if needed, then download file via CDP."""
    res = ChallengeResolutionT({})
    res.status = STATUS_OK

    # Step 1: Navigate and solve challenge (same as _evil_logic)
    logging.debug(f"Navigating to... {req.url}")
    driver.get(req.url)

    # Wait for Cloudflare challenge
    page_title = driver.title
    challenge_found = any(title.lower() == page_title.lower() for title in CHALLENGE_TITLES)

    if challenge_found:
        logging.info("Challenge detected for download. Title: " + page_title)
        attempt = 0
        while True:
            try:
                attempt += 1
                for title in CHALLENGE_TITLES:
                    WebDriverWait(driver, SHORT_TIMEOUT).until_not(title_is(title))
                for selector in CHALLENGE_SELECTORS:
                    WebDriverWait(driver, SHORT_TIMEOUT).until_not(
                        presence_of_element_located((By.CSS_SELECTOR, selector)))
                break
            except TimeoutException:
                click_verify(driver)
                driver.find_element(By.TAG_NAME, "html")

        try:
            WebDriverWait(driver, SHORT_TIMEOUT).until(
                staleness_of(driver.find_element(By.TAG_NAME, "html")))
        except Exception:
            pass
        logging.info("Challenge solved for download!")

    # Step 1.5: Wait for non-Cloudflare challenges (AWS WAF, etc.)
    # Some sites use JS challenges that FlareSolverr doesn't detect by title.
    # Detect them by checking page source for known patterns, then wait.
    _wait_start = time.time()
    _max_challenge_wait = 15  # seconds

    while time.time() - _wait_start < _max_challenge_wait:
        try:
            page_source = driver.page_source or ''
        except Exception:
            page_source = ''

        # AWS WAF challenge
        has_waf_challenge = 'awsWafCookieDomainList' in page_source
        # Generic JS challenge indicators
        has_js_challenge = ('challenge' in page_source.lower()[:2000]
                           and len(page_source) < 5000
                           and '<form' not in page_source.lower()[:2000])

        if has_waf_challenge or has_js_challenge:
            if time.time() - _wait_start < 1:  # Log only once
                logging.info(f"JS challenge detected (WAF={has_waf_challenge}), waiting for completion...")
            time.sleep(1)
        else:
            break

    if time.time() - _wait_start >= 2:
        logging.info(f"JS challenge wait completed in {time.time() - _wait_start:.1f}s")

    # Step 2: Determine the fetch URL.
    # After navigation, the browser may have been redirected to a CDN domain
    # (e.g. watermark02.silverchair.com, pdf.sciencedirectassets.com).
    # Use the current URL (which is same-origin) to avoid CORS issues.
    current_url = driver.current_url
    target_origin = f"{urlparse(req.url).scheme}://{urlparse(req.url).netloc}"
    current_origin = f"{urlparse(current_url).scheme}://{urlparse(current_url).netloc}"

    # Detect browser internal URLs (download triggered native file save, tab is empty)
    is_internal_url = current_url.startswith(('chrome://', 'about:', 'data:'))

    if is_internal_url:
        # Browser triggered a native download, tab is empty.
        # Navigate to the target base URL, then JS fetch the original URL.
        logging.info(f"Native download detected (current={current_url[:40]}), "
                     f"navigating to {target_origin} for JS fetch...")
        driver.get(target_origin)

        # Wait for possible Cloudflare challenge on base URL
        page_title = driver.title
        if any(title.lower() == page_title.lower() for title in CHALLENGE_TITLES):
            logging.info("Challenge detected on base URL. Title: " + page_title)
            attempt = 0
            while True:
                try:
                    attempt += 1
                    for title in CHALLENGE_TITLES:
                        WebDriverWait(driver, SHORT_TIMEOUT).until_not(title_is(title))
                    for selector in CHALLENGE_SELECTORS:
                        WebDriverWait(driver, SHORT_TIMEOUT).until_not(
                            presence_of_element_located((By.CSS_SELECTOR, selector)))
                    break
                except TimeoutException:
                    click_verify(driver)
                    driver.find_element(By.TAG_NAME, "html")
            try:
                WebDriverWait(driver, SHORT_TIMEOUT).until(
                    staleness_of(driver.find_element(By.TAG_NAME, "html")))
            except Exception:
                pass
            logging.info("Challenge solved on base URL!")

        fetch_url = req.url
    elif current_origin != target_origin:
        # Redirected to CDN domain, fetch from there (same-origin)
        fetch_url = current_url
        logging.info(f"Redirected to {current_origin}, will fetch: {fetch_url[:80]}")
    else:
        fetch_url = req.url

    # Step 3: Download file via JS fetch in the browser context.
    # The browser is on the same origin as fetch_url, so no CORS issues.
    file_base64 = None

    logging.info("Downloading file via JS fetch in browser context...")
    try:
        js_result = driver.execute_async_script("""
            var url = arguments[0];
            var callback = arguments[arguments.length - 1];
            fetch(url)
                .then(r => {
                    if (!r.ok) {
                        callback({error: 'HTTP ' + r.status + ' ' + r.statusText});
                        return;
                    }
                    return r.blob();
                })
                .then(blob => {
                    if (!blob) return;
                    var reader = new FileReader();
                    reader.onloadend = () => callback({
                        data: reader.result.split(',')[1],
                        size: blob.size,
                        type: blob.type
                    });
                    reader.onerror = () => callback({error: 'FileReader error'});
                    reader.readAsDataURL(blob);
                })
                .catch(e => callback({error: e.toString()}));
        """, fetch_url)

        if isinstance(js_result, dict):
            if 'error' in js_result:
                raise Exception(f"JS fetch error: {js_result['error']}")
            if 'data' in js_result:
                file_base64 = js_result['data']
                logging.info(f"JS fetch success: {js_result.get('size', '?')} bytes, "
                             f"type: {js_result.get('type', '?')}")
    except Exception as e:
        logging.error(f"JS fetch failed: {e}")

    if file_base64 is None:
        raise Exception("Failed to download file content")

    # Build response
    challenge_res = ChallengeResolutionResultT({})
    challenge_res.url = current_url
    challenge_res.status = 200
    challenge_res.cookies = driver.get_cookies()
    challenge_res.userAgent = utils.get_user_agent(driver)
    challenge_res.fileBase64 = file_base64
    res.message = "File downloaded successfully"
    res.result = challenge_res

    v1_res = V1ResponseBase({})
    v1_res.status = res.status
    v1_res.message = res.message
    v1_res.solution = res.result
    return v1_res


def _cmd_request_post(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.postData is None:
        raise Exception("Request parameter 'postData' is mandatory in 'request.post' command.")
    if req.returnRawHtml is not None:
        logging.warning("Request parameter 'returnRawHtml' was removed in FlareSolverr v2.")
    if req.download is not None:
        logging.warning("Request parameter 'download' was removed in FlareSolverr v2.")

    challenge_res = _resolve_challenge(req, 'POST')
    res = V1ResponseBase({})
    res.status = challenge_res.status
    res.message = challenge_res.message
    res.solution = challenge_res.result
    return res


def _cmd_sessions_create(req: V1RequestBase) -> V1ResponseBase:
    logging.debug("Creating new session...")

    session, fresh = SESSIONS_STORAGE.create(session_id=req.session, proxy=req.proxy)
    session_id = session.session_id

    if not fresh:
        return V1ResponseBase({
            "status": STATUS_OK,
            "message": "Session already exists.",
            "session": session_id
        })

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "Session created successfully.",
        "session": session_id
    })


def _cmd_sessions_list(req: V1RequestBase) -> V1ResponseBase:
    session_ids = SESSIONS_STORAGE.session_ids()

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "",
        "sessions": session_ids
    })


def _cmd_sessions_destroy(req: V1RequestBase) -> V1ResponseBase:
    session_id = req.session
    existed = SESSIONS_STORAGE.destroy(session_id)

    if not existed:
        raise Exception("The session doesn't exist.")

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "The session has been removed."
    })


def _resolve_challenge(req: V1RequestBase, method: str) -> ChallengeResolutionT:
    timeout = int(req.maxTimeout) / 1000
    driver = None
    try:
        if req.session:
            session_id = req.session
            ttl = timedelta(minutes=req.session_ttl_minutes) if req.session_ttl_minutes else None
            session, fresh = SESSIONS_STORAGE.get(session_id, ttl)

            if fresh:
                logging.debug(f"new session created to perform the request (session_id={session_id})")
            else:
                logging.debug(f"existing session is used to perform the request (session_id={session_id}, "
                              f"lifetime={str(session.lifetime())}, ttl={str(ttl)})")

            driver = session.driver
        else:
            driver = utils.get_webdriver(req.proxy)
            logging.debug('New instance of webdriver has been created to perform the request')
        return func_timeout(timeout, _evil_logic, (req, driver, method))
    except FunctionTimedOut:
        raise Exception(f'Error solving the challenge. Timeout after {timeout} seconds.')
    except Exception as e:
        raise Exception('Error solving the challenge. ' + str(e).replace('\n', '\\n'))
    finally:
        if not req.session and driver is not None:
            if utils.PLATFORM_VERSION == "nt":
                driver.close()
            driver.quit()
            logging.debug('A used instance of webdriver has been destroyed')


def click_verify(driver: WebDriver, num_tabs: int = 1):
    try:
        logging.debug("Try to find the Cloudflare verify checkbox...")
        actions = ActionChains(driver)
        actions.pause(5)
        for _ in range(num_tabs):
            actions.send_keys(Keys.TAB).pause(0.1)
        actions.pause(1)
        actions.send_keys(Keys.SPACE).perform()
        
        logging.debug(f"Cloudflare verify checkbox clicked after {num_tabs} tabs!")
    except Exception:
        logging.debug("Cloudflare verify checkbox not found on the page.")
    finally:
        driver.switch_to.default_content()

    try:
        logging.debug("Try to find the Cloudflare 'Verify you are human' button...")
        button = driver.find_element(
            by=By.XPATH,
            value="//input[@type='button' and @value='Verify you are human']",
        )
        if button:
            actions = ActionChains(driver)
            actions.move_to_element_with_offset(button, 5, 7)
            actions.click(button)
            actions.perform()
            logging.debug("The Cloudflare 'Verify you are human' button found and clicked!")
    except Exception:
        logging.debug("The Cloudflare 'Verify you are human' button not found on the page.")

    time.sleep(2)

def _get_turnstile_token(driver: WebDriver, tabs: int):
    token_input = driver.find_element(By.CSS_SELECTOR, "input[name='cf-turnstile-response']")
    current_value = token_input.get_attribute("value")
    while True:
        click_verify(driver, num_tabs=tabs)
        turnstile_token = token_input.get_attribute("value")
        if turnstile_token:
            if turnstile_token != current_value:
                logging.info(f"Turnstile token: {turnstile_token}")
                return turnstile_token
        logging.debug(f"Failed to extract token possibly click failed")        

        # reset focus
        driver.execute_script("""
            let el = document.createElement('button');
            el.style.position='fixed';
            el.style.top='0';
            el.style.left='0';
            document.body.prepend(el);
            el.focus();
        """)
        time.sleep(1)

def _resolve_turnstile_captcha(req: V1RequestBase, driver: WebDriver):
    turnstile_token = None
    if req.tabs_till_verify is not None:
        logging.debug(f'Navigating to... {req.url} in order to pass the turnstile challenge')
        driver.get(req.url)

        turnstile_challenge_found = False
        for selector in TURNSTILE_SELECTORS:
            found_elements = driver.find_elements(By.CSS_SELECTOR, selector)   
            if len(found_elements) > 0:
                turnstile_challenge_found = True
                logging.info("Turnstile challenge detected. Selector found: " + selector)
                break
        if turnstile_challenge_found:
            turnstile_token = _get_turnstile_token(driver=driver, tabs=req.tabs_till_verify)
        else:
            logging.debug(f'Turnstile challenge not found')
    return turnstile_token

def _evil_logic(req: V1RequestBase, driver: WebDriver, method: str) -> ChallengeResolutionT:
    res = ChallengeResolutionT({})
    res.status = STATUS_OK
    res.message = ""

    # optionally block resources like images/css/fonts using CDP
    disable_media = utils.get_config_disable_media()
    if req.disableMedia is not None:
        disable_media = req.disableMedia
    if disable_media:
        block_urls = [
            # Images
            "*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.bmp", "*.svg", "*.ico",
            "*.PNG", "*.JPG", "*.JPEG", "*.GIF", "*.WEBP", "*.BMP", "*.SVG", "*.ICO",
            "*.tiff", "*.tif", "*.jpe", "*.apng", "*.avif", "*.heic", "*.heif",
            "*.TIFF", "*.TIF", "*.JPE", "*.APNG", "*.AVIF", "*.HEIC", "*.HEIF",
            # Stylesheets
            "*.css",
            "*.CSS",
            # Fonts
            "*.woff", "*.woff2", "*.ttf", "*.otf", "*.eot",
            "*.WOFF", "*.WOFF2", "*.TTF", "*.OTF", "*.EOT"
        ]
        try:
            logging.debug("Network.setBlockedURLs: %s", block_urls)
            driver.execute_cdp_cmd("Network.enable", {})
            driver.execute_cdp_cmd("Network.setBlockedURLs", {"urls": block_urls})
        except Exception:
            # if CDP commands are not available or fail, ignore and continue
            logging.debug("Network.setBlockedURLs failed or unsupported on this webdriver")

    # navigate to the page
    logging.debug(f"Navigating to... {req.url}")
    turnstile_token = None

    if method == "POST":
        _post_request(req, driver)
    else:
        if req.tabs_till_verify is None:
            driver.get(req.url)
        else:
            turnstile_token = _resolve_turnstile_captcha(req, driver)

    # set cookies if required
    if req.cookies is not None and len(req.cookies) > 0:
        logging.debug(f'Setting cookies...')
        for cookie in req.cookies:
            driver.delete_cookie(cookie['name'])
            driver.add_cookie(cookie)
        # reload the page
        if method == 'POST':
            _post_request(req, driver)
        else:
            driver.get(req.url)

    # wait for the page
    if utils.get_config_log_html():
        logging.debug(f"Response HTML:\n{driver.page_source}")
    html_element = driver.find_element(By.TAG_NAME, "html")
    page_title = driver.title

    # find access denied titles
    for title in ACCESS_DENIED_TITLES:
        if page_title.startswith(title):
            raise Exception('Cloudflare has blocked this request. '
                            'Probably your IP is banned for this site, check in your web browser.')
    # find access denied selectors
    for selector in ACCESS_DENIED_SELECTORS:
        found_elements = driver.find_elements(By.CSS_SELECTOR, selector)
        if len(found_elements) > 0:
            raise Exception('Cloudflare has blocked this request. '
                            'Probably your IP is banned for this site, check in your web browser.')

    # find challenge by title
    challenge_found = False
    for title in CHALLENGE_TITLES:
        if title.lower() == page_title.lower():
            challenge_found = True
            logging.info("Challenge detected. Title found: " + page_title)
            break
    if not challenge_found:
        # find challenge by selectors
        for selector in CHALLENGE_SELECTORS:
            found_elements = driver.find_elements(By.CSS_SELECTOR, selector)
            if len(found_elements) > 0:
                challenge_found = True
                logging.info("Challenge detected. Selector found: " + selector)
                break

    attempt = 0
    if challenge_found:
        while True:
            try:
                attempt = attempt + 1
                # wait until the title changes
                for title in CHALLENGE_TITLES:
                    logging.debug("Waiting for title (attempt " + str(attempt) + "): " + title)
                    WebDriverWait(driver, SHORT_TIMEOUT).until_not(title_is(title))

                # then wait until all the selectors disappear
                for selector in CHALLENGE_SELECTORS:
                    logging.debug("Waiting for selector (attempt " + str(attempt) + "): " + selector)
                    WebDriverWait(driver, SHORT_TIMEOUT).until_not(
                        presence_of_element_located((By.CSS_SELECTOR, selector)))

                # all elements not found
                break

            except TimeoutException:
                logging.debug("Timeout waiting for selector")

                click_verify(driver)

                # update the html (cloudflare reloads the page every 5 s)
                html_element = driver.find_element(By.TAG_NAME, "html")

        # waits until cloudflare redirection ends
        logging.debug("Waiting for redirect")
        # noinspection PyBroadException
        try:
            WebDriverWait(driver, SHORT_TIMEOUT).until(staleness_of(html_element))
        except Exception:
            logging.debug("Timeout waiting for redirect")

        logging.info("Challenge solved!")
        res.message = "Challenge solved!"
    else:
        logging.info("Challenge not detected!")
        res.message = "Challenge not detected!"

    challenge_res = ChallengeResolutionResultT({})
    challenge_res.url = driver.current_url
    challenge_res.status = 200  # todo: fix, selenium not provides this info
    challenge_res.cookies = driver.get_cookies()
    challenge_res.userAgent = utils.get_user_agent(driver)
    challenge_res.turnstile_token = turnstile_token

    if not req.returnOnlyCookies:
        challenge_res.headers = {}  # todo: fix, selenium not provides this info

        if req.waitInSeconds and req.waitInSeconds > 0:
            logging.info("Waiting " + str(req.waitInSeconds) + " seconds before returning the response...")
            time.sleep(req.waitInSeconds)

        challenge_res.response = driver.page_source

    if req.returnScreenshot:
        challenge_res.screenshot = driver.get_screenshot_as_base64()

    res.result = challenge_res
    return res


def _post_request(req: V1RequestBase, driver: WebDriver):
    post_form = f'<form id="hackForm" action="{req.url}" method="POST">'
    query_string = req.postData if req.postData and req.postData[0] != '?' else req.postData[1:] if req.postData else ''
    pairs = query_string.split('&')
    for pair in pairs:
        parts = pair.split('=', 1)
        # noinspection PyBroadException
        try:
            name = unquote(parts[0])
        except Exception:
            name = parts[0]
        if name == 'submit':
            continue
        # noinspection PyBroadException
        try:
            value = unquote(parts[1]) if len(parts) > 1 else ''
        except Exception:
            value = parts[1] if len(parts) > 1 else ''
        # Protection of " character, for syntax
        value=value.replace('"','&quot;')
        post_form += f'<input type="text" name="{escape(quote(name))}" value="{escape(quote(value))}"><br>'
    post_form += '</form>'
    html_content = f"""
        <!DOCTYPE html>
        <html>
        <body>
            {post_form}
            <script>document.getElementById('hackForm').submit();</script>
        </body>
        </html>"""
    driver.get("data:text/html;charset=utf-8,{html_content}".format(html_content=html_content))

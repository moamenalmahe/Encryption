import sys
import os
import json
from cryptography.fernet import Fernet
import hashlib
import zipfile
from PyQt5.QtCore import Qt, QPoint, QUrl, QSettings  # Import QUrl and QSettings
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QFileDialog, QLineEdit, QLabel, QMessageBox, QInputDialog, QScrollArea, QDialog
from PyQt5.QtGui import QFont, QImage, QPixmap, QPalette, QBrush
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEngineSettings, QWebEngineProfile  # Import QWebEngineView, QWebEngineSettings, and QWebEngineProfile
import random
import string
from PyQt5.QtWebEngineCore import QWebEngineUrlRequestInterceptor
import io
import base64

class Encryptor:
    def __init__(self):
        # Cache for loaded keys to avoid repeated disk reads
        self._key_cache = {}
        
        # Generate a deterministic backup key using a constant phrase
        backup_phrase = b'APP_SPECIFIC_BACKUP_KEY_DO_NOT_MODIFY_OR_SHARE_v1'
        # Create a 32-byte key using SHA256 and encode it properly for Fernet
        backup_key = base64.urlsafe_b64encode(hashlib.sha256(backup_phrase).digest())
        self._backup_fernet = Fernet(backup_key)

    def key_create(self):
        return Fernet.generate_key()

    def key_write(self, key, key_name):
        with open(key_name, 'wb') as mykey:
            mykey.write(key)

    def key_load(self, key_name):
        if key_name in self._key_cache:
            return self._key_cache[key_name]

        if not os.path.isabs(key_name):
            script_dir = os.path.dirname(os.path.realpath(__file__))
            key_name = os.path.join(script_dir, key_name)
        
        if os.path.exists(key_name):
            with open(key_name, 'rb') as mykey:
                key = mykey.read()
                self._key_cache[key_name] = key
                return key
        else:
            raise FileNotFoundError(f"Key file not found: {key_name}")

    def file_encrypt(self, key, original_file, encrypted_file):
        f = Fernet(key)
        with open(original_file, 'rb') as file:
            original = file.read()
        encrypted = f.encrypt(original)
        with open(encrypted_file, 'wb') as file:
            file.write(encrypted)

    def file_decrypt(self, key, encrypted_file, decrypted_file):
        f = Fernet(key)
        with open(encrypted_file, 'rb') as file:
            encrypted = file.read()
        decrypted = f.decrypt(encrypted)
        with open(decrypted_file, 'wb') as file:
            file.write(decrypted)

    def create_backup(self, key_file, backup_code, backup_path):
        # Create a temporary zip in memory
        temp_zip_data = io.BytesIO()
        with zipfile.ZipFile(temp_zip_data, 'w', zipfile.ZIP_DEFLATED) as temp_zip:
            # Add files to zip with specific header
            temp_zip.comment = b'ENCRYPTED_BACKUP_V1'  # Version identifier
            
            # Add key file
            with open(key_file, 'rb') as f:
                temp_zip.writestr(os.path.basename(key_file), f.read())
            
            # Add settings if exists
            if os.path.exists("settings.json"):
                with open("settings.json", 'rb') as f:
                    temp_zip.writestr("settings.json", f.read())
            
            # Add backup code hash
            hashed_code = hashlib.sha256(backup_code.encode()).hexdigest()
            temp_zip.writestr("backup_code.hash", hashed_code)

        # Encrypt the entire zip file
        zip_data = temp_zip_data.getvalue()
        encrypted_data = self._backup_fernet.encrypt(zip_data)
        
        # Save encrypted backup
        with open(backup_path, 'wb') as f:
            f.write(encrypted_data)
        
        return backup_path

    def verify_backup_code(self, backup_code, backup_file):
        try:
            # Read and decrypt backup
            with open(backup_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Verify it's our backup format
            decrypted_data = self._backup_fernet.decrypt(encrypted_data)
            temp_zip = io.BytesIO(decrypted_data)
            
            with zipfile.ZipFile(temp_zip) as backup_zip:
                if backup_zip.comment != b'ENCRYPTED_BACKUP_V1':
                    raise ValueError("Invalid backup file format")
                
                with backup_zip.open("backup_code.hash") as f:
                    stored_hashed_code = f.read().decode()
                    
            hashed_code = hashlib.sha256(backup_code.encode()).hexdigest()
            return hashed_code == stored_hashed_code
        except Exception as e:
            print(f"Verification error: {e}")
            return False

    def restore_backup(self, backup_file):
        try:
            # Read and decrypt backup
            with open(backup_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self._backup_fernet.decrypt(encrypted_data)
            temp_zip = io.BytesIO(decrypted_data)
            
            # Extract to temporary directory
            script_dir = os.path.dirname(os.path.realpath(__file__))
            extract_dir = os.path.join(script_dir, "backup_restore")
            os.makedirs(extract_dir, exist_ok=True)
            
            with zipfile.ZipFile(temp_zip) as backup_zip:
                if backup_zip.comment != b'ENCRYPTED_BACKUP_V1':
                    raise ValueError("Invalid backup file format")
                backup_zip.extractall(path=extract_dir)
            
            # Handle restoration with dual locations
            key_file_path = None
            for name in os.listdir(extract_dir):
                if name.endswith(".gkey"):
                    key_file_path = os.path.join(extract_dir, name)
                    
                    # Save to root folder
                    root_key_path = os.path.join(script_dir, name)
                    if os.path.exists(root_key_path):
                        os.remove(root_key_path)
                    # Use copy2 to preserve metadata
                    import shutil
                    shutil.copy2(key_file_path, root_key_path)
                    
                    # Keep copy in backup_restore
                    # Key file already exists there from extractall
                    break
            
            # Restore settings if present
            settings_path = os.path.join(extract_dir, "settings.json")
            if os.path.exists(settings_path):
                target_settings = os.path.join(script_dir, "settings.json")
                if os.path.exists(target_settings):
                    os.remove(target_settings)
                os.rename(settings_path, target_settings)
            
            if key_file_path:
                return os.path.basename(key_file_path)
            else:
                raise FileNotFoundError("Key file not found in the backup")
                
        except Exception as e:
            raise Exception(f"Failed to restore backup: {e}")

class RequestInterceptor(QWebEngineUrlRequestInterceptor):
    def __init__(self, parent=None):
        super().__init__(parent)
        # Convert blocked_domains to a set for O(1) lookup
        self.blocked_domains = set([
            # Existing domains...
            'doubleclick.net', 'google-analytics.com', 'googleadservices.com', 
            'googlesyndication.com', 'adnxs.com', 'serving-sys.com', 'amazon-adsystem.com',
            'moatads.com', 'adform.net', 'casalemedia.com', 'adzerk.net', 'bidswitch.net',
            'buysellads.com', 'carbonads.com', 'content.ad', 'criteo.com', 'disqus.com',
            'exponential.com', 'getclicky.com', 'heapanalytics.com',
            'facebook.com', 'fb.com', 'fbcdn.net', 'twitter.com', 'linkedin.com', 
            'instagram.com', 'pinterest.com', 'snapchat.com', 'tiktok.com',
            'connect.facebook.net', 'platform.twitter.com', 'ads.linkedin.com',
            'ads.pinterest.com', 'sc-static.net', 'ads.tiktok.com',
            'google-analytics.com', 'googletagmanager.com', 'googletagservices.com',
            'analytics.google.com', 'marketingplatform.google.com', 'hotjar.com',
            'mouseflow.com', 'kissmetrics.com', 'mixpanel.com', 'segment.com',
            'statcounter.com', 'quantserve.com', 'qualaroo.com', 'optimizely.com',
            'crazyegg.com', 'clicktale.net', 'inspectlet.com', 'mouseflow.com',
            'luckyorange.com', 'fullstory.com', 'loggly.com', 'rollbar.com',
            'adroll.com', 'advertising.com', 'appnexus.com', 'mediamath.com',
            'pubmatic.com', 'rubiconproject.com', 'taboola.com', 'outbrain.com',
            'revcontent.com', 'sharethrough.com', 'tapad.com', 'turn.com',
            'unity3d.com', 'yandex.ru', 'adtech.com', 'amung.us', 'bbelements.com',
            'tracking.', 'metrics.', 'telemetry.', 'analytics.', 'stats.',
            'counter.', 'pixel.', 'log.', 'beacon.', 'monitor.', 'trace.',
            'collect.', 'track.', 'targeting.', 'measurements.', 'audience.',
            'adition.com', 'adsafeprotected.com', 'adsrvr.org', 'adtechus.com',
            'eqads.com', 'everesttech.net', 'flashtalking.com', 'innovid.com',
            'linksynergy.com', 'mookie1.com', 'nuggad.net', 'omnitagjs.com',
            'smartadserver.com', 'undertone.com', 'videohub.tv', 'yieldlab.net',
            # Additional Ad Networks
            'adcolony.com', 'admob.com', 'chitika.com', 'inmobi.com', 'leadbolt.com',
            'millennialmedia.com', 'mopub.com', 'revmob.com', 'smaato.com', 'startapp.com',
            'tapjoy.com', 'vungle.com', 'mdotm.com', 'adtech.de', 'adbrite.com',
            'adbuddiz.com', 'adcash.com', 'adversal.com', 'propellerads.com',
            'exoclick.com', 'clicksor.com', 'popads.net', 'adf.ly', 'adrecover.com',
            # Additional Analytics Services
            'amplitude.com', 'appsflyer.com', 'adjust.com', 'branch.io', 'kochava.com',
            'localytics.com', 'flurry.com', 'umeng.com', 'newrelic.com', 'crashlytics.com',
            'heap.io', 'woopra.com', 'clicky.com', 'gauges.com', 'piwik.org',
            'matomo.org', 'chartbeat.com', 'parsely.com', 'alexa.com', 'histats.com',
            # More Social Media Trackers
            'api.facebook.', 'graph.facebook.', 'pixel.facebook.',
            'analytics.twitter.', 'ads.twitter.', 'static.ads-twitter.',
            'linkedin.com/analytics', 'linkedin.com/pixel', 'ads.linkedin.',
            'analytics.pinterest.', 'log.pinterest.', 'trk.pinterest.',
            'analytics.tiktok.', 'ads.tiktok.', 'log.byteoversea.',
            # Video Ad Networks
            'fwmrm.net', 'innovid.com', 'spotxchange.com', 'tremorhub.com',
            'teads.tv', 'streamrail.net', 'stickyadstv.com', 'brightroll.com',
            'videohub.tv', 'tubemogul.com', 'yieldmo.com', 'springserve.com',
            # Additional Tracking Services
            'acxiom.com', 'addthis.com', 'adentifi.com', 'adsymptotic.com',
            'bluekai.com', 'brilig.com', 'datalogix.com', 'exelator.com',
            'lotame.com', 'media6degrees.com', 'nexac.com', 'quantcast.com',
            'rapleaf.com', 'turn.com', 'tynt.com', 'datalogix.com',
            # Crypto Mining and Resource Abuse
            'coinhive.com', 'crypto-loot.com', 'minr.pw', 'coin-hive.com',
            'jsecoin.com', 'reasedoper.pw', 'mataharirama.xyz', 'listat.biz',
            'lmodr.biz', 'minecrunch.co', 'minemytraffic.com', 'crypto-webminer.com'
        ])
        
        # Compile patterns for faster matching
        import re
        self.blocked_patterns = [re.compile(pattern) for pattern in [
            '/ads/', '/analytics/', '/tracking/', '/pixel/', '/banner/',
            '/googleads/', '/adsense/', '/doubleclick/', '/beacon/',
            '/sponsored/', '/targeting/', '/adtrack/', '/adserver/',
            '/pagead/', '/affiliate/', '/clicktrack/', '/telemetry/',
            '/conversions/', '/prebid/', '/retargeting/', '/bidder/',
            '/marketing/', '/optimize/', '/fingerprint/', '/impression/',
            '/eventtrack/', '/statistics/', '/engagement/', '/attribution/',
            '/remarketing/', '/audience/', '/gtm/', '/utm_', '/dcm/',
            '/collect', '/counter', '/protocol', '/subscribe', '/metrics',
            '/analysis', '/profiling', '/behaviour', '/traffic', '/visitor',
            '/ntrack/', '/ptrack/', '/etrack/', '/ctrack/', '/itrack/',
            '/mtrack/', '/strack/', '/dtrack/', '/rtrack/', '/ftrack/',
            '/analytics-', '/tracking-', '/tracking_', '/analytics_',
            '/statistic', '/counter', '/analyze/', '/ga.js', '/ga_',
            '/chartbeat', '/beacon', '/pixel', '/log.', '/logging.',
            '/stats.', '/collect', '/track.', '/track-', '/track_',
            '/adunit', '/adframe', '/adspace', '/adbox', '/adsky',
            '/pop.js', '/pop_', '/pop-', '/popunder', '/popup',
            '/fingerprint', '/impression', '/viewability', '/heatmap'
        ]]
        
        # Optimize tracking params lookup
        self.tracking_params = set([
            'utm_', 'fbclid', 'gclid', '_ga', '_gid', 'msclkid',
            'mc_', 'yclid', 'dclid', '_openstat', 'fb_', 'igshid',
            'vero_', 'ml_', 'rb_', 'sc_', '_branch_', '_bta_',
            'trk_', 'mc_', 'ns_', 'ic_', 'ref_', 'oref', 'eref',
            'pref', 'cmp_', 'cxd', 'mkwid', 'pcrid', 'pkw', 'pmt',
            'pgrid', 'plid', 'sc_', 'ko_click_id', 'hs_', 'hsa_'
        ])

        # Add blocked resources dictionary
        self.blocked_resources = {
            'script': ['.ads.', '.analytics.', '.tracking.', '.stats.'],
            'image': ['pixel', 'beacon', 'tracking', 'counter'],
            'xmlhttprequest': ['collect', 'stats', 'telemetry', 'track'],
            'other': ['fingerprint', 'profile', 'monitor'],
            'media': ['ad-', '-ad-', '_ad_', 'advert', 'promo'],
            'stylesheet': ['ads', 'track', 'analytics'],
            'websocket': ['track', 'analytics', 'metrics'],
            'fetch': ['collect', 'analytics', 'metrics', 'track']
        }

    def interceptRequest(self, info):
        url = info.requestUrl().toString().lower()
        request_type = info.resourceType()
        
        # Block by domain
        if any(domain in url for domain in self.blocked_domains):
            info.block(True)
            return

        # Block by pattern
        if any(pattern.search(url) for pattern in self.blocked_patterns):
            info.block(True)
            return
        
        # Block by resource type and content
        resource_type = str(request_type).lower()
        for rtype, patterns in self.blocked_resources.items():
            if rtype in resource_type:
                if any(pattern in url for pattern in patterns):
                    info.block(True)
                    return

        # Enhanced parameter blocking
        parsed_url = url.split('?')
        if len(parsed_url) > 1:
            query_params = parsed_url[1].split('&')
            if any(param.startswith(tuple(self.tracking_params)) for param in query_params):
                info.block(True)
                return

        # Block by first-party URL characteristics
        if any(term in url for term in [
            'tracking', 'analytics', 'telemetry', 'metrics',
            'beacon', 'pixel', 'advertisement', 'banner',
            'profiling', 'targeting', 'marketing'
        ]):
            info.block(True)
            return

class App(QWidget):
    def __init__(self):
        super().__init__()

        # Initialize style cache variables
        self._stylesheet = None
        self._button_style = None

        self.setWindowTitle("File Encryptor & Decryptor")
        self.setGeometry(100, 100, 1200, 600)

        # Initialize drag position
        self._drag_position = None

        # Create Encryptor instance
        self.encryptor = Encryptor()
        self.key = None
        self.key_file_name = None  # Store the key filename
        self.background_image_path = None  # Store the background image path
        self.settings = self.load_settings()

        # Set up the overall layout
        self.layout = QHBoxLayout(self)

        # Create a side navigation bar
        self.create_sidebar()

        # Create the content area (right side)
        self.content_layout = QVBoxLayout()
        self.create_content_area()

        self.layout.addLayout(self.sidebar_layout)
        self.layout.addLayout(self.content_layout)

        self.setWindowFlag(Qt.FramelessWindowHint)
        
        # Apply background and styles in correct order
        self.set_background_image()
        self.apply_styles()
        
        # Initialize web settings
        self.web_settings = QWebEngineSettings.defaultSettings()
        self.setup_web_settings()
        
        # Flag to track if web view is loaded
        self.web_view_loaded = False

    def set_background_image(self):
        if self.background_image_path and os.path.exists(self.background_image_path):
            try:
                oImage = QImage(self.background_image_path)
                if not oImage.isNull():
                    sImage = oImage.scaled(self.size(), Qt.IgnoreAspectRatio, Qt.SmoothTransformation)
                    palette = QPalette()
                    palette.setBrush(QPalette.Window, QBrush(sImage))
                    self.setPalette(palette)
                    self._cached_background = self.background_image_path
                    self.setAutoFillBackground(True)
                    print(f"Background set successfully from: {self.background_image_path}")
                else:
                    print("Failed to load background image: Image is null")
            except Exception as e:
                print(f"Error setting background: {e}")
        else:
            if self.background_image_path:
                print(f"Background image not found: {self.background_image_path}")
            # Set default background color if no image
            palette = QPalette()
            palette.setColor(QPalette.Window, Qt.black)
            self.setPalette(palette)
            self.setAutoFillBackground(True)

    def apply_styles(self):
        """Apply stylesheet after background is set"""
        self.setStyleSheet(self.get_stylesheet())

    def resizeEvent(self, event):
        super().resizeEvent(event)  # Call super first
        self.set_background_image()  # Then update background

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_position = event.globalPos()
            event.accept()

    def mouseMoveEvent(self, event):
        if self._drag_position:
            delta = event.globalPos() - self._drag_position
            self.move(self.x() + delta.x(), self.y() + delta.y())
            self._drag_position = event.globalPos()
            event.accept()

    def mouseReleaseEvent(self, event):
        self._drag_position = None
        event.accept()

    def create_sidebar(self):
        self.sidebar_layout = QVBoxLayout()
        self.sidebar_layout.setSpacing(10)

        self.title = QLabel("Encryption GUI", self)
        self.title.setFont(QFont("Arial", 24, QFont.Bold))
        self.title.setAlignment(Qt.AlignCenter)
        # Add style to match content title
        self.title.setStyleSheet("""
            QLabel {
                background-color: rgba(0, 0, 0, 0.5);
                border-radius: 10px;
                padding: 10px;
                margin-bottom: 10px;
                color: white;
            }
        """)
        self.sidebar_layout.addWidget(self.title)

        self.generate_key_button = self.create_button("Generate Key", self.generate_key)
        self.load_key_button = self.create_button("Load Key", self.load_key)
        self.encrypt_file_button = self.create_button("Encrypt File", self.encrypt_file)
        self.decrypt_file_button = self.create_button("Decrypt File", self.decrypt_file)
        self.create_backup_button = self.create_button("Create a Backup", self.create_backup)
        self.restore_backup_button = self.create_button("Restore from a Backup", self.restore_backup)
        self.verify_backup_code_button = self.create_button("Verify Key Backup", self.verify_backup_code)
        self.set_background_button = self.create_button("Set Background Image", self.set_background_image_path)
        
        self.sidebar_layout.addWidget(self.generate_key_button)
        self.sidebar_layout.addWidget(self.load_key_button)
        self.sidebar_layout.addWidget(self.encrypt_file_button)
        self.sidebar_layout.addWidget(self.decrypt_file_button)
        self.sidebar_layout.addWidget(self.create_backup_button)
        self.sidebar_layout.addWidget(self.restore_backup_button)
        self.sidebar_layout.addWidget(self.verify_backup_code_button)
        self.sidebar_layout.addWidget(self.set_background_button)

        # Add version label before exit button
        self.version_label = QLabel("v4.0", self)
        self.version_label.setFont(QFont("Arial", 8))
        self.version_label.setAlignment(Qt.AlignCenter)
        self.version_label.setStyleSheet("""
            QLabel {
                background-color: rgba(0, 0, 0, 0.5);  /* Match other elements' transparency */
                color: rgba(255, 255, 255, 0.9);       /* Brighter text */
                border-radius: 5px;
                padding: 5px;
                margin-bottom: 5px;
                font-weight: bold;
            }
        """)

        # Create a container for exit button and version label
        exit_container = QWidget()
        exit_layout = QVBoxLayout(exit_container)
        exit_layout.setSpacing(2)
        exit_container.setStyleSheet("background: transparent;")  #/* Make container transparent */
        
        # Style the exit button with a more subtle color scheme
        self.exit_button = QPushButton("Exit", self)
        self.exit_button.setFont(QFont("Arial", 12))
        self.exit_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(80, 80, 80, 0.75);  /* Changed opacity to 0.75 */
                color: white;
                border-radius: 10px;
                padding: 10px;
                font-size: 14px;
                border: 1px solid rgba(255, 255, 255, 0.1);
            }
            QPushButton:hover {
                background-color: rgba(90, 90, 90, 0.75);  /* Changed opacity to 0.75 */
                border: 1px solid rgba(255, 255, 255, 0.2);
            }
            QPushButton:pressed {
                background-color: rgba(70, 70, 70, 0.75);  /* Changed opacity to 0.75 */
                border: 1px solid rgba(255, 255, 255, 0.3);
            }
        """)
        self.exit_button.clicked.connect(self.close)

        # Add version label and exit button to container
        exit_layout.addWidget(self.version_label)
        exit_layout.addWidget(self.exit_button)

        # Update sidebar layout
        self.sidebar_layout.addStretch(1)  # Push everything up
        self.sidebar_layout.addWidget(exit_container)  # Add container at bottom

    def create_content_area(self):
        # Create main content container
        self.content_container = QWidget()
        self.content_container_layout = QVBoxLayout(self.content_container)
        
        # Create and setup the label that will contain the web view
        self.content_title = QLabel("Welcome to Encryption GUI", self)
        self.content_title.setFont(QFont("Arial", 24, QFont.Bold))
        self.content_title.setAlignment(Qt.AlignCenter)
        
        # Unified style for both title and content container
        title_style = """
            QLabel, QWidget {
                background-color: rgba(0, 0, 0, 0.5);
                border-radius: 10px;
                padding: 10px;
                margin-bottom: 10px;
                color: white;
            }
        """
        self.content_title.setStyleSheet(title_style)
        self.content_container.setStyleSheet(title_style)
        
        # Create web container with matching style - increase height
        self.web_container = QWidget(self.content_title)
        self.web_container_layout = QVBoxLayout(self.web_container)
        self.web_container.setFixedSize(850, 500)  # Increased from 500 to 700
        self.web_container.setStyleSheet("background-color: rgba(0, 0, 0, 0.5); border-radius: 10px;")
        
        # Initialize web view with optimized settings - increase height to match container
        self.web_view = QWebEngineView(self.web_container)
        self.web_view.setFixedSize(830, 465)  # Increased from 480 to 680
        
        # Add web view directly to container without navigation controls
        self.web_container_layout.addWidget(self.web_view)
        self.content_container_layout.addWidget(self.content_title)
        self.content_container_layout.addWidget(self.web_container)
        
        # Add the container to the main content layout
        self.content_layout.addWidget(self.content_container)
        
        # Load initial URL
        self.load_url("https://mot204t.github.io/Encryption-GUI/site/index.html")

        # Add privacy features to web view
        if hasattr(self, 'web_view'):
            page = self.web_view.page()
            page.profile().setHttpCacheType(QWebEngineProfile.MemoryHttpCache)
            page.profile().setPersistentCookiesPolicy(QWebEngineProfile.NoPersistentCookies)
            
            # Set initial random fingerprint
            self.randomize_fingerprint()

        # Inject content blocking JavaScript
        js_code = """
        // Block common tracking scripts
        const blockTrackingScripts = () => {
            const observer = new MutationObserver((mutations) => {
                mutations.forEach((mutation) => {
                    mutation.addedNodes.forEach((node) => {
                        if (node.tagName === 'SCRIPT' || node.tagName === 'IMG' || node.tagName === 'IFRAME') {
                            const src = node.src || '';
                            if (src.includes('ads') || src.includes('analytics') || src.includes('tracking')) {
                                node.remove();
                            }
                        }
                    });
                });
            });
            
            observer.observe(document, {
                childList: true,
                subtree: true
            });
        };
        
        // Execute when DOM is ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', blockTrackingScripts);
        } else {
            blockTrackingScripts();
        }
        """
        self.web_view.page().runJavaScript(js_code)

    def load_url(self, url):
        if hasattr(self, 'web_view'):
            # Randomize fingerprint before loading new URL
            self.randomize_fingerprint()
            self.web_view.setUrl(QUrl(url))

    def closeEvent(self, event):
        # Cleanup web view resources
        if self.web_view:
            self.web_view.deleteLater()
            QWebEngineProfile.defaultProfile().clearAllVisitedLinks()
            QWebEngineProfile.defaultProfile().clearHttpCache()
        
        # Call parent's closeEvent
        super().closeEvent(event)

    def setup_web_settings(self):
        # Optimize memory usage
        profile = QWebEngineProfile.defaultProfile()
        profile.clearHttpCache()
        profile.setHttpCacheType(QWebEngineProfile.MemoryHttpCache)
        profile.setPersistentCookiesPolicy(QWebEngineProfile.NoPersistentCookies)
        
        # Configure web settings for better performance
        self.web_settings.setAttribute(QWebEngineSettings.JavascriptEnabled, True)
        self.web_settings.setAttribute(QWebEngineSettings.ScrollAnimatorEnabled, False)
        self.web_settings.setAttribute(QWebEngineSettings.PluginsEnabled, False)
        self.web_settings.setAttribute(QWebEngineSettings.AutoLoadImages, True)
        self.web_settings.setAttribute(QWebEngineSettings.WebGLEnabled, False)

        # Enhanced privacy settings
        profile = QWebEngineProfile.defaultProfile()
        
        # Block third-party cookies
        profile.setPersistentCookiesPolicy(QWebEngineProfile.NoPersistentCookies)
        
        # Disable storage APIs
        self.web_settings.setAttribute(QWebEngineSettings.LocalStorageEnabled, False)
        # Remove WebStorageEnabled as it's not available
        self.web_settings.setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, False)
        self.web_settings.setAttribute(QWebEngineSettings.AllowRunningInsecureContent, False)
        
        # Additional privacy protections
        self.web_settings.setAttribute(QWebEngineSettings.AutoLoadIconsForPage, False)
        self.web_settings.setAttribute(QWebEngineSettings.WebRTCPublicInterfacesOnly, True)
        self.web_settings.setAttribute(QWebEngineSettings.HyperlinkAuditingEnabled, False)
        
        # Set up request interceptor with enhanced blocking
        self.interceptor = RequestInterceptor()
        profile.setUrlRequestInterceptor(self.interceptor)
        
        # Additional headers to prevent tracking
        profile.setHttpUserAgent(self.generate_random_user_agent())
        profile.setHttpAcceptLanguage("en-US,en;q=0.9")
        profile.setHttpCacheType(QWebEngineProfile.NoCache)

    def randomize_user_agent(self, profile):
        profile.setHttpUserAgent(self.generate_random_user_agent())

    def generate_random_user_agent(self):
        # List of common browsers and their UA strings
        browsers = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
        ]
        
        # Generate random version numbers
        major = random.randint(70, 120)
        minor = random.randint(0, 9)
        build = random.randint(1000, 9999)
        
        base_ua = random.choice(browsers)
        return f"{base_ua} RandomizedClient/{major}.{minor}.{build}"

    def randomize_fingerprint(self):
        if hasattr(self, 'web_view'):
            profile = self.web_view.page().profile()
            self.randomize_user_agent(profile)
            
            # Override JavaScript fingerprinting APIs
            js_code = """
            () => {
                const randomInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
                
                // Override properties commonly used for fingerprinting
                Object.defineProperties(navigator, {
                    hardwareConcurrency: { value: randomInt(2, 16) },
                    deviceMemory: { value: randomInt(2, 32) },
                    platform: { value: ['Win32', 'MacIntel', 'Linux x86_64'][randomInt(0, 2)] },
                });
                
                // Override screen properties
                Object.defineProperties(screen, {
                    width: { value: [1920, 2560, 3440][randomInt(0, 2)] },
                    height: { value: [1080, 1440, 2160][randomInt(0, 2)] },
                });
            }
            """
            self.web_view.page().runJavaScript(js_code)

    def create_button(self, text, callback=None):
        button = QPushButton(text, self)
        button.setFont(QFont("Arial", 12))
        button.setStyleSheet(self.button_style())
        if callback:
            button.clicked.connect(callback)
        return button

    def load_key(self):
        key_file, _ = QFileDialog.getOpenFileName(self, "Open GKey", "", "GKey files (*.gkey)")
        if key_file:
            try:
                self.key = self.encryptor.key_load(key_file)
                self.key_file_name = key_file  # Store the key filename
                if self.ask_save_key_preference():
                    self.settings["saved_key"] = key_file
                    self.save_settings()
                    QMessageBox.information(self, "Key Saved", "Key location has been saved for future use.")
                self.update_window_title("Key Loaded")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error loading key: {e}")

    def generate_key(self):
        try:
            key_file, _ = QFileDialog.getSaveFileName(self, "Save GKey", "", "GKey files (*.gkey)")
            if key_file:
                # Generate and write key
                key = self.encryptor.key_create()
                self.encryptor.key_write(key, key_file)
                
                # Update instance variables
                self.key = key
                self.key_file_name = key_file
                
                # Handle settings
                if self.ask_save_key_preference():
                    if not hasattr(self, 'settings'):
                        self.settings = {}
                    self.settings["saved_key"] = key_file
                    self.save_settings()
                    QMessageBox.information(self, "Key Saved", "Key location has been saved for future use.")
                
                self.update_window_title("Key Generated and Saved")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate key: {str(e)}")
            print(f"Error generating key: {e}")  # Debug logging

    def ask_save_key_preference(self):
        """Ask if user wants to save the key location for future use"""
        reply = QMessageBox.question(
            self, 
            'Save Key Location',
            'Would you like to save this key location for future use?\n\n'
            'This will automatically load the key when you start the application.',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes
        )
        return reply == QMessageBox.Yes

    def load_settings(self):
        # Cache settings file path
        if not hasattr(self, '_settings_path'):
            script_dir = os.path.dirname(os.path.realpath(__file__))
            self._settings_path = os.path.join(script_dir, "settings.json")
        
        settings_data = {}
        if os.path.exists(self._settings_path):
            try:
                with open(self._settings_path, 'r') as f:
                    settings_data = json.load(f)
                    
                    # Handle saved key if it exists
                    if "saved_key" in settings_data:
                        key_path = settings_data["saved_key"]
                        if not os.path.isabs(key_path):
                            key_path = os.path.join(os.path.dirname(self._settings_path), key_path)
                        if os.path.exists(key_path):
                            try:
                                self.key = self.encryptor.key_load(key_path)
                                self.key_file_name = key_path
                                print(f"Successfully loaded saved key from: {key_path}")
                            except Exception as e:
                                print(f"Error loading saved key: {e}")
                    
                    # Handle background if it exists
                    if "background" in settings_data:
                        bg_path = settings_data["background"]
                        if not os.path.isabs(bg_path):
                            bg_path = os.path.join(os.path.dirname(self._settings_path), bg_path)
                        if os.path.exists(bg_path):
                            self.background_image_path = bg_path
                            print(f"Background path set to: {bg_path}")
                        else:
                            print(f"Background image not found: {bg_path}")
                            self.background_image_path = None
                    
            except json.JSONDecodeError as e:
                print(f"Error loading settings: {e}")
                settings_data = {}
        
        return settings_data

    def save_settings(self):
        """Save settings to JSON file"""
        try:
            # Create settings directory if it doesn't exist
            settings_dir = os.path.dirname(self._settings_path)
            os.makedirs(settings_dir, exist_ok=True)
            
            # Use atomic write operation with a temporary file
            temp_path = self._settings_path + '.tmp'
            with open(temp_path, 'w') as f:
                json.dump(self.settings, f, indent=4)
            
            # Atomic replace
            if os.path.exists(self._settings_path):
                os.replace(temp_path, self._settings_path)
            else:
                os.rename(temp_path, self._settings_path)
            
            print(f"Settings saved successfully to: {self._settings_path}")
        except Exception as e:
            print(f"Error saving settings: {e}")
            raise

    def encrypt_file(self):
        if not self.key:
            QMessageBox.warning(self, "Error", "No key loaded or generated.")
            return

        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if file_path:
            save_path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted File", "", "Encrypted files (*.enc)")
            if save_path:
                try:
                    self.encryptor.file_encrypt(self.key, file_path, save_path)
                    self.update_window_title(f"File encrypted: {os.path.basename(save_path)}")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Error encrypting file: {e}")

    def decrypt_file(self):
        if not self.key:
            QMessageBox.warning(self, "Error", "No key loaded or generated.")
            return

        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt")
        if file_path:
            save_path, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File", "", "All files (*)")
            if save_path:
                try:
                    self.encryptor.file_decrypt(self.key, file_path, save_path)
                    self.update_window_title(f"File decrypted: {os.path.basename(save_path)}")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Error decrypting file: {e}")

    def create_backup(self):
        if not self.key_file_name:
            QMessageBox.warning(self, "Error", "No key file loaded.")
            return

        # Create a custom dialog for backup creation
        dialog = QDialog(self)
        dialog.setWindowTitle("Create Backup")
        dialog.setMinimumWidth(400)
        layout = QVBoxLayout()

        # Add instructions
        info_label = QLabel("Create a secure backup of your encryption key and settings.\n"
                          "Please enter a strong backup code you'll remember.", dialog)
        info_label.setWordWrap(True)
        info_label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 14px;
                background-color: rgba(0, 0, 0, 0.5);
                padding: 10px;
                border-radius: 5px;
            }
        """)
        layout.addWidget(info_label)

        # Add backup code input
        backup_code_input = QLineEdit(dialog)
        backup_code_input.setPlaceholderText("Enter Backup Code")
        backup_code_input.setEchoMode(QLineEdit.Password)
        backup_code_input.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border-radius: 5px;
                background: rgba(255, 255, 255, 0.1);
                color: white;
                border: 1px solid rgba(255, 255, 255, 0.2);
            }
        """)
        layout.addWidget(backup_code_input)

        # Add buttons
        button_layout = QHBoxLayout()
        create_button = QPushButton("Create Backup", dialog)
        cancel_button = QPushButton("Cancel", dialog)
        
        for btn in [create_button, cancel_button]:
            btn.setStyleSheet(self.button_style())
            button_layout.addWidget(btn)
        
        layout.addLayout(button_layout)
        dialog.setLayout(layout)
        
        # Set dialog style
        dialog.setStyleSheet("""
            QDialog {
                background-color: rgba(44, 44, 44, 0.95);
                border-radius: 10px;
            }
        """)

        # Connect buttons
        cancel_button.clicked.connect(dialog.reject)
        create_button.clicked.connect(lambda: self._create_backup_action(dialog, backup_code_input.text()))
        
        dialog.exec_()

    def _create_backup_action(self, dialog, backup_code):
        if len(backup_code) < 6:
            QMessageBox.warning(self, "Warning", "Please enter a backup code with at least 6 characters.")
            return
        
        try:
            # Let user choose where to save the backup file
            backup_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Backup File",
                "key-backup.genc",  
                "Backup files (*.genc)"  
            )
            
            if not backup_path:  # User cancelled
                return
            
            backup_file = self.encryptor.create_backup(self.key_file_name, backup_code, backup_path)
            QMessageBox.information(self, "Success", 
                                  f"Backup created successfully!\n\n"
                                  f"Backup file: {backup_file}\n\n"
                                  "Please store your backup code safely. You'll need it to restore the backup.")
            dialog.accept()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create backup: {str(e)}")

    def restore_backup(self):
        # Create a custom dialog for backup restoration
        dialog = QDialog(self)
        dialog.setWindowTitle("Restore Backup")
        dialog.setMinimumWidth(400)
        layout = QVBoxLayout()

        # Add instructions
        info_label = QLabel("Restore your encryption key and settings from a backup.\n"
                          "You'll need your backup file and backup code.", dialog)
        info_label.setWordWrap(True)
        info_label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 14px;
                background-color: rgba(0, 0, 0, 0.5);
                padding: 10px;
                border-radius: 5px;
            }
        """)
        layout.addWidget(info_label)

        # Add file selection button
        select_file_button = QPushButton("Select Backup File", dialog)
        select_file_button.setStyleSheet(self.button_style())
        layout.addWidget(select_file_button)

        # Add backup code input
        backup_code_input = QLineEdit(dialog)
        backup_code_input.setPlaceholderText("Enter Backup Code")
        backup_code_input.setEchoMode(QLineEdit.Password)
        backup_code_input.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border-radius: 5px;
                background: rgba(255, 255, 255, 0.1);
                color: white;
                border: 1px solid rgba(255, 255, 255, 0.2);
            }
        """)
        layout.addWidget(backup_code_input)

        # Add buttons
        button_layout = QHBoxLayout()
        restore_button = QPushButton("Restore Backup", dialog)
        cancel_button = QPushButton("Cancel", dialog)
        
        for btn in [restore_button, cancel_button]:
            btn.setStyleSheet(self.button_style())
            button_layout.addWidget(btn)
        
        layout.addLayout(button_layout)
        dialog.setLayout(layout)
        
        # Set dialog style
        dialog.setStyleSheet("""
            QDialog {
                background-color: rgba(44, 44, 44, 0.95);
                border-radius: 10px;
            }
        """)

        # Store selected file path
        selected_file = [""]  # Using list to modify in lambda

        # Connect buttons
        def select_file():
            file, _ = QFileDialog.getOpenFileName(dialog, "Select Backup File", "", "Backup files (*.genc)")  
            if file:
                selected_file[0] = file
                select_file_button.setText("Selected: " + os.path.basename(file))

        select_file_button.clicked.connect(select_file)
        cancel_button.clicked.connect(dialog.reject)
        restore_button.clicked.connect(lambda: self._restore_backup_action(
            dialog, selected_file[0], backup_code_input.text()))
        
        dialog.exec_()

    def _restore_backup_action(self, dialog, backup_file, backup_code):
        if not backup_file:
            QMessageBox.warning(self, "Warning", "Please select a backup file.")
            return
        
        if len(backup_code) == 0:
            QMessageBox.warning(self, "Warning", "Please enter your backup code.")
            return

        try:
            # First verify the backup code
            if not self.encryptor.verify_backup_code(backup_code, backup_file):
                QMessageBox.critical(self, "Error", "Invalid backup code.")
                return

            # If verification successful, proceed with restoration
            key_file_path = self.encryptor.restore_backup(backup_file)
            QMessageBox.information(self, "Success", 
                                  f"Backup restored successfully!\n\n"
                                  f"Key file restored: {key_file_path}\n\n"
                                  "Please restart the application to load the restored settings.")
            dialog.accept()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to restore backup: {str(e)}")

    def verify_backup_code(self):
        # Create a custom dialog for backup verification
        dialog = QDialog(self)
        dialog.setWindowTitle("Verify Backup Code")
        dialog.setMinimumWidth(400)
        layout = QVBoxLayout()

        # Add instructions
        info_label = QLabel("Verify your backup file and backup code.\n"
                          "You'll need your backup file and the backup code you used.", dialog)
        info_label.setWordWrap(True)
        info_label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 14px;
                background-color: rgba(0, 0, 0, 0.5);
                padding: 10px;
                border-radius: 5px;
            }
        """)
        layout.addWidget(info_label)

        # Add file selection button
        select_file_button = QPushButton("Select Backup File", dialog)
        select_file_button.setStyleSheet(self.button_style())
        layout.addWidget(select_file_button)

        # Add backup code input
        backup_code_input = QLineEdit(dialog)
        backup_code_input.setPlaceholderText("Enter Backup Code")
        backup_code_input.setEchoMode(QLineEdit.Password)
        backup_code_input.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border-radius: 5px;
                background: rgba(255, 255, 255, 0.1);
                color: white;
                border: 1px solid rgba(255, 255, 255, 0.2);
            }
        """)
        layout.addWidget(backup_code_input)

        # Add buttons
        button_layout = QHBoxLayout()
        verify_button = QPushButton("Verify Backup", dialog)
        cancel_button = QPushButton("Cancel", dialog)
        
        for btn in [verify_button, cancel_button]:
            btn.setStyleSheet(self.button_style())
            button_layout.addWidget(btn)
        
        layout.addLayout(button_layout)
        dialog.setLayout(layout)
        
        # Set dialog style
        dialog.setStyleSheet("""
            QDialog {
                background-color: rgba(44, 44, 44, 0.95);
                border-radius: 10px;
            }
        """)

        # Store selected file path
        selected_file = [""]  # Using list to modify in lambda

        # Connect buttons
        def select_file():
            file, _ = QFileDialog.getOpenFileName(dialog, "Select Backup File", "", "Backup files (*.genc)")  
            if file:
                selected_file[0] = file
                select_file_button.setText("Selected: " + os.path.basename(file))

        select_file_button.clicked.connect(select_file)
        cancel_button.clicked.connect(dialog.reject)
        verify_button.clicked.connect(lambda: self._verify_backup_action(
            dialog, selected_file[0], backup_code_input.text()))
        
        dialog.exec_()

    def _verify_backup_action(self, dialog, backup_file, backup_code):
        if not backup_file:
            QMessageBox.warning(self, "Warning", "Please select a backup file.")
            return
        
        if len(backup_code) == 0:
            QMessageBox.warning(self, "Warning", "Please enter your backup code.")
            return

        try:
            valid = self.encryptor.verify_backup_code(backup_code, backup_file)
            if valid:
                QMessageBox.information(self, "Verification Success", 
                                      "The backup code is valid for this backup file.")
            else:
                QMessageBox.critical(self, "Verification Failed", 
                                   "The backup code is not valid for this backup file.")
            dialog.accept()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to verify backup: {str(e)}")

    def set_background_image_path(self):
        image_file, _ = QFileDialog.getOpenFileName(self, "Select Background Image", "", "Image files (*.png *.jpg *.jpeg)")
        if image_file:
            self.background_image_path = image_file
            self.settings["background"] = image_file
            self.save_settings()
            self.set_background_image()
            self.update_window_title("Background Image Set")

    def update_window_title(self, title):
        self.setWindowTitle(f"File Encryptor & Decryptor - {title}")

    def get_stylesheet(self):
        # Cache stylesheet
        if self._stylesheet is None:
            self._stylesheet = """
            QWidget {
                background-color: rgba(44, 44, 44, 0.85); /* More opaque background instead of backdrop-filter */
                border-radius: 12px;
                padding: 20px;
            }

            QLabel {
                color: white;
                font-family: 'Arial', sans-serif;
                font-size: 24px;
                font-weight: bold;
            }

            QLineEdit {
                background-color: rgba(255, 255, 255, 0.3); /* Light background for input fields */
                color: white;
                border: 1px solid #888888;
                border-radius: 8px;
                padding: 12px;
                font-size: 16px;
            }

            QLineEdit:focus {
                border: 1px solid #ffffff;
            }

            QPushButton {
                background-color: rgba(0, 0, 0, 0.7); /* Dark background for buttons */
                color: white;
                border: 1px solid #444444;
                border-radius: 10px;
                padding: 15px;
                font-size: 16px;
            }

            QPushButton:hover {
                background-color: rgba(51, 51, 51, 0.8);
                border: 1px solid #666666;
            }

            QPushButton:pressed {
                background-color: rgba(34, 34, 34, 0.8);
            }

            QPushButton:focus {
                border: 1px solid #ffffff;
            }

            QMessageBox {
                background-color: rgba(0, 0, 0, 0.85); /* More opaque background instead of backdrop-filter */
                color: white;
                border-radius: 8px;
                padding: 20px;
            }

            QMessageBox QLabel {
                font-size: 18px;
            }

            QMessageBox QPushButton {
                background-color: rgba(51, 51, 51, 0.8);
                color: white;
                border-radius: 8px;
                padding: 8px 15px;
                font-size: 14px;
            }

            QMessageBox QPushButton:hover {
                background-color: rgba(68, 68, 68, 0.8);
            }

            QMessageBox QPushButton:pressed {
                background-color: rgba(34, 34, 34, 0.8);
            }

            QMessageBox QIcon {
                width: 35px;
                height: 35px;
            }
            """
        return self._stylesheet

    def button_style(self):
        # Cache button style
        if self._button_style is None:
            self._button_style = """
            QPushButton {
                background-color: rgba(0, 0, 0, 0.7);
                color: white;
                border-radius: 10px;
                padding: 10px;
                font-size: 14px;
            }

            QPushButton:hover {
                background-color: rgba(51, 51, 51, 0.8);
            }

            QPushButton:pressed {
                background-color: rgba(34, 34, 34, 0.8);
            }

            QPushButton:focus {
                border: 1px solid #ffffff;
            }
            """
        return self._button_style

# Start the application
if __name__ == "__main__":
    # Enable high DPI support
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    
    app = QApplication(sys.argv)
    
    # Set application-wide attributes
    app.setStyle('Fusion')  # More efficient style
    
    window = App()
    window.show()
    
    sys.exit(app.exec_())


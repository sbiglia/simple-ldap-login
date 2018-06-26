<?php
/*
  Plugin Name: Custom LDAP Login
  Plugin URI: http://happycoderstudio.com/custom-ldap-login/
  Description:  Adds multi-domain LDAP authentication to WP.
  Version: 1.0.0
  Author: Sebastian Biglia.
  Author URI: http://happycoderstudio.com
 */

class CustomLDAPLogin
{

    private static $prefix_s = "cldapl_";
    static $instance = false;
    var $prefix;
    var $settings = array();
    var $adldap;
    var $ldap;
    var $network_version = null;
    var $version = "0.9";
    var $errors = array();

    var $edit_domain = array();

    // openssl constants
    private static $openssl_method = "AES-256-CBC";

    private static function get_openssl_pass()
    {
        return gethostname();
    }

    public static function get_field_settings_s()
    {
        return CustomLDAPLogin::$prefix_s . "settings";
    }


    public function __construct()
    {
        $this->edit_domain = $this->get_empty_domain();

        $this->prefix = CustomLDAPLogin::$prefix_s;
        $this->settings = $this->get_settings_obj();
        /*
                if (trim($this->get_setting('directory')) == "ad") {
                    require_once( plugin_dir_path(__FILE__) . "/includes/adLDAP.php" );

                    try {
                        $this->create_adldap();
                    } catch (adLDAPException $e) {
                        // Disable SSO
                        $this->set_setting('sso_enabled', FALSE);

                        // try create adldap again
                        $this->create_adldap();
                    }
                }*/

        add_action('admin_init', array($this, 'handle_request'));

        if ($this->is_network_version()) {
            add_action('network_admin_menu', array($this, 'menu'));
        } else {
            add_action('admin_menu', array($this, 'menu'));
        }


        if (str_true($this->get_setting('enabled'))) {
            //add_filter('authenticate', array($this, 'authenticate'), 1, 3);
        }

        register_activation_hook(__FILE__, array($this, 'activate'));

        // If version is false, and old version detected, run activation
        if ($this->get_setting('version') === false || $this->get_setting('version') != $this->version) {
            $this->upgrade_settings();
        }

        // Registering SSO function
        if (str_true($this->get_setting('sso_enabled'))) {
            add_action('init', array($this, 'login_sso'));
        }
    }

    function create_adldap()
    {
        $this->adldap = new adLDAP(
            array(
                "account_suffix" => trim($this->get_setting('account_suffix')),
                "use_tls" => str_true($this->get_setting('use_tls')),
                "base_dn" => trim($this->get_setting('base_dn')),
                "domain_controllers" => (array)$this->get_setting('domain_controllers'),
                "ad_port" => (int)$this->get_setting('ldap_port'),
                "ad_username" => $this->is_sso_enabled() ? $this->get_setting('sso_search_user') : NULL,
                "ad_password" => $this->is_sso_enabled() ? $this->get_sso_search_user_pass() : NULL
            )
        );
    }

    private function is_valid_call_sso()
    {
        //  Skip login page
        if (parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH) === "/wp-login.php") {
            return false;
        }
        return true;
    }

    // SSO Implementation
    function login_sso()
    {
        // Respect current login
        if (!is_user_logged_in() && $this->is_sso_configuration_ok() && $this->is_valid_call_sso()) {
            // Automatic login 
            $usu = $this->authenticate(NULL, $this->get_sso_logged_user(), $this->get_sso_logged_user(), TRUE);
            wp_set_current_user($usu->ID, $usu->user_login);
            wp_set_auth_cookie($usu->ID);
            do_action('wp_login', $usu->user_login, $usu);
        }
    }

    public static function getInstance()
    {
        if (!self::$instance) {
            self::$instance = new self;
        }
        return self::$instance;
    }

    function activate()
    {
        // Default settings
        $this->add_setting('domains', array());

        // SSO settings
        $this->add_setting('sso_enabled', "false");
        $this->add_setting('sso_search_user', "");
        $this->add_setting('sso_search_user_password', "");

        // User attribute settings
        $this->add_setting('user_first_name_attribute', "givenname");
        $this->add_setting('user_last_name_attribute', "sn");
        $this->add_setting('user_email_attribute', "mail");
        $this->add_setting('user_url_attribute', "wwwhomepage");
        $this->add_setting('user_meta_data', array());
        $this->add_setting('meta_data_suffix_ldap', 'ldap');
        $this->add_setting('meta_data_suffix_wp', 'wp');
    }

    function get_empty_domain()
    {
        return [
            'id' => 0,
            'name' => "",
            'account_suffix' => "",
            'base_dn' => "",
            'domain_controllers' => [""],
            'directory' => "ad",
            'role' => "contributor",
            'ol_login' => "uid",
            'ol_group' => "cn",
            'use_tls' => "false",
            'ldap_port' => 389,
            'ldap_version' => 3,
            'create_users' => "false",
            'enabled' => "false",
            'search_sub_ous' => "false",
            'group_base_dn' => "",
            'login_domain' => "",
            'groups' => [""]
        ];
    }

    function upgrade_settings()
    {
        /*
        $currentVersion = $this->get_setting('version');

        // Update version
        $this->set_setting('version', $this->version);

        if ($currentVersion == "0.8") {
            $this->set_setting('domains', array());
        } else {

            // Default settings
            $defaultDomain = [
                [
                    'id' => 0,
                    'domain_data' => [
                        'name' => 'default',
                        'account_suffix' => "@mydomain.org",
                        'base_dn' => "DC=mydomain,DC=org",
                        'domain_controller' => ["dc01.mydomain.local"],
                        'directory' => "ad",
                        'role' => "contributor",
                        'ol_login' => "uid",
                        'ol_group' => "cn",
                        'use_tls' => "false",
                        'ldap_port' => 389,
                        'ldap_version' => 3,
                        'create_users' => "false",
                        'enabled' => "false",
                        'search_sub_ous' => "false",
                        'group_dn' => "",
                        'group_uid' => "memberUid"
                    ]
                ]
            ];

            $this->add_setting('domains', $defaultDomain);
        }*/
    }

    function menu()
    {
        if ($this->is_network_version()) {
            add_submenu_page(
                "settings.php", "Custom LDAP Login", "Custom LDAP Login", 'manage_network_plugins', "simple-ldap-login", array($this, 'admin_page')
            );
        } else {
            add_options_page("Custom LDAP Login", "Custom LDAP Login", 'manage_options', "simple-ldap-login", array($this, 'admin_page'));
        }
    }

    function admin_page()
    {
        include 'Custom-LDAP-Login_Admin.php';
    }

    function get_settings_obj()
    {
        if ($this->is_network_version()) {
            return get_site_option(CustomLDAPLogin::get_field_settings_s(), false);
        } else {
            return get_option(CustomLDAPLogin::get_field_settings_s(), false);
        }
    }

    function set_settings_obj($newobj)
    {
        if ($this->is_network_version()) {
            return update_site_option(CustomLDAPLogin::get_field_settings_s(), $newobj);
        } else {
            return update_option(CustomLDAPLogin::get_field_settings_s(), $newobj);
        }
    }

    function set_setting($option = false, $newvalue)
    {
        if ($option === false)
            return false;

        $this->settings = $this->get_settings_obj($this->prefix);
        $this->settings[$option] = $newvalue;
        return $this->set_settings_obj($this->settings);
    }

    function get_setting($option = false)
    {
        if ($option === false || !isset($this->settings[$option]))
            return false;

        return apply_filters($this->prefix . 'get_setting', $this->settings[$option], $option);
    }

    function add_setting($option = false, $newvalue)
    {
        if ($option === false)
            return false;

        if (!isset($this->settings[$option])) {
            return $this->set_setting($option, $newvalue);
        } else {
            return false;
        }
    }

    function get_field_name($setting, $type = 'string')
    {
        return "{$this->prefix}setting[$setting][$type]";
    }

    function save_settings()
    {
        if (isset($_REQUEST["{$this->prefix}setting"]) && check_admin_referer('add_domain', 'save_the_cll')) {
            $new_settings = stripslashes_deep($_REQUEST["{$this->prefix}setting"]);

            foreach ($new_settings as $setting_name => $setting_value) {
                foreach ($setting_value as $type => $value) {
                    if ($setting_name == 'user_meta_data') {
                        $this->set_setting($setting_name, array_map(function ($attr) {
                            return explode(':', trim($attr));
                        }, array_filter(preg_split('/\r\n|\n|\r|;/', trim($value)))));
                    } elseif ($type == "array") {
                        $this->set_setting($setting_name, explode(";", $value));
                    } elseif ($type == "password") {
                        if (!empty($value)) {
                            $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length(self::$openssl_method));
                            $encrypt = openssl_encrypt($value, self::$openssl_method, self::get_openssl_pass(), 0, $iv);
                            $this->set_setting($setting_name, "{$encrypt};" . bin2hex($iv));
                        }
                    } else {
                        $this->set_setting($setting_name, $value);
                    }
                }
            }

            if ($this->is_network_version()) {
                add_action('network_admin_notices', array($this, 'saved_admin_notice'));
            } else {
                add_action('admin_notices', array($this, 'saved_admin_notice'));
            }
        }
    }

    function handle_request()
    {
        /*if (!isset($_REQUEST["{$this->prefix}setting"])) {
            return;
        }*/
        if (!isset($_POST['save_the_cll'])) {
            return;
        }

        if (wp_verify_nonce($_POST['save_the_cll'], 'add_domain')) {

            $request = $this->parse_request_data($_REQUEST["{$this->prefix}setting"]);
            $this->add_domain($request);

        } elseif (wp_verify_nonce($_POST['save_the_cll'], 'update_domains')) {

            if (isset($_POST['deleteit'])) {
                $this->delete_domain($_POST['delete']);
            } elseif (isset($_POST['updateit'])) {
                $this->update_domain($_POST['enable']);
            }

        } elseif (wp_verify_nonce($_POST['save_the_cll'], 'delete_domains')) {
            $request = $this->parse_request_data($_REQUEST["{$this->prefix}setting"]);
        } elseif (wp_verify_nonce($_POST['save_the_cll'], 'enable_disable_domains')) {
            $request = $this->parse_request_data($_REQUEST["{$this->prefix}setting"]);
        } elseif (wp_verify_nonce($_POST['save_the_cll'], 'save_sso_settings')) {
            $request = $this->parse_request_data($_REQUEST["{$this->prefix}setting"]);
        } elseif (wp_verify_nonce($_POST['save_the_cll'], 'save_user_settings')) {
            $request = $this->parse_request_data($_REQUEST["{$this->prefix}setting"]);
        }
        /*
        $new_settings = stripslashes_deep($_REQUEST["{$this->prefix}setting"]);

        foreach ($new_settings as $setting_name => $setting_value) {
            foreach ($setting_value as $type => $value) {
                if ($setting_name == 'user_meta_data') {
                    $this->set_setting($setting_name, array_map(function ($attr) {
                        return explode(':', trim($attr));
                    }, array_filter(preg_split('/\r\n|\n|\r|;/', trim($value)))));
                } elseif ($type == "array") {
                    $this->set_setting($setting_name, explode(";", $value));
                } elseif ($type == "password") {
                    if (!empty($value)) {
                        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length(self::$openssl_method));
                        $encrypt = openssl_encrypt($value, self::$openssl_method, self::get_openssl_pass(), 0, $iv);
                        $this->set_setting($setting_name, "{$encrypt};" . bin2hex($iv));
                    }
                } else {
                    $this->set_setting($setting_name, $value);
                }
            }
        }

        if ($this->is_network_version()) {
            add_action('network_admin_notices', array($this, 'saved_admin_notice'));
        } else {
            add_action('admin_notices', array($this, 'saved_admin_notice'));
        }*/

    }

    function parse_request_data($request)
    {
        $parsed_array = array();

        foreach ($request as $setting_name => $setting_value) {
            foreach ($setting_value as $type => $value) {
                if ($setting_name == 'user_meta_data') {
                    $parsed_array[$setting_name] = array_map(function ($attr) {
                        return explode(':', trim($attr));
                    }, array_filter(preg_split('/\r\n|\n|\r|;/', trim($value))));
                } elseif ($type == "array") {
                    $parsed_array[$setting_name] = explode(";", $value);
                } elseif ($type == "password") {
                    if (!empty($value)) {
                        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length(self::$openssl_method));
                        $encrypt = openssl_encrypt($value, self::$openssl_method, self::get_openssl_pass(), 0, $iv);
                        $parsed_array[$setting_name] = "{$encrypt};" . bin2hex($iv);
                    }
                } else {
                    $parsed_array[$setting_name] = $value;
                }
            }
        }

        return $parsed_array;

    }

    function update_sso_settings($data)
    {

    }

    function add_domain($data)
    {

        $this->errors = array();

        $this->edit_domain['name'] = $data['name'];
        $this->edit_domain['account_suffix'] = $data['account_suffix'];
        $this->edit_domain['base_dn'] = $data['base_dn'];
        $this->edit_domain['domain_controllers'] = $data['domain_controllers'];
        $this->edit_domain['directory'] = $data['directory'];
        $this->edit_domain['role'] = $data['role'];
        $this->edit_domain['ol_login'] = $data['ol_login'];
        $this->edit_domain['ol_group'] = $data['ol_group'];
        $this->edit_domain['use_tls'] = $data['use_tls'];
        $this->edit_domain['ldap_port'] = $data['ldap_port'];
        $this->edit_domain['ldap_version'] = $data['ldap_version'];
        $this->edit_domain['create_users'] = $data['create_users'];
        $this->edit_domain['search_sub_ous'] = $data['search_sub_ous'];
        $this->edit_domain['group_base_dn'] = $data['group_base_dn'];
        $this->edit_domain['login_domain'] = $data['login_domain'];
        $this->edit_domain['groups'] = $data['groups'];

        if (!isset($data['name']) || empty($data['name'])) {
            $this->errors[] = ['message' => 'Domain name not set.', 'type' => 'error'];
        }

        if (!isset($data['base_dn']) || empty($data['base_dn'])) {
            $this->errors[] = ['message' => 'Base DN name not set.', 'type' => 'error'];
        }

        if (!isset($data['account_suffix']) || empty($data['account_suffix'])) {
            $this->errors[] = ['message' => 'Account suffix not set.', 'type' => 'error'];
        }

        if (!isset($data['domain_controllers']) || count($data['domain_controllers']) == 0 || empty($data['domain_controllers'][0])) {
            $this->errors[] = ['message' => 'At least one domain controller must be set.', 'type' => 'error'];
        }

        if (count($this->errors) > 0) {
            foreach ($this->errors as $error) {
                add_settings_error("cll_settings_messages", "settings", $error['message'], $error['type']);
            }

            //settings_errors('cll_settings_messages');
            return;
        }

        $this->edit_domain['id'] = $this->get_next_domain_id();
        $this->edit_domain['enabled'] = 'true';
        $this->settings['domains'][] = $this->edit_domain;
        $this->edit_domain = $this->get_empty_domain();
        $this->set_settings_obj($this->settings);

        add_settings_error("cll_settings_messages", "settings", 'New domain ' . $data['name'] . ' added successfully.', 'updated');

    }

    function update_domain($data)
    {

        foreach ($this->settings['domains'] as &$domain) {
            if(!isset($data)){
                $domain['enabled'] = 'false';
            }
            else{

                if(in_array($domain['id'], $data)){
                    $domain['enabled'] = 'true';
                }else{
                    $domain['enabled'] = 'false';
                }
            }
        }

        $this->set_settings_obj($this->settings);

        add_settings_error("cll_settings_messages", "settings", 'Domain(s) enable/disable status successfully updated.', 'updated');

    }

    function delete_domain($to_delete)
    {
        foreach ($to_delete as $delete) {
            foreach ($this->settings['domains'] as $key => $domain) {
                if ($domain['id'] == $delete) {
                    unset($this->settings['domains'][$key]);
                }
            }
        }

        $this->set_settings_obj($this->settings);

        add_settings_error("cll_settings_messages", "settings", 'Domain(s) successfully deleted.', 'updated');
    }

    function enable_disable_domains($data)
    {

    }

    function update_user_settings($data)
    {

    }

    function get_next_domain_id()
    {
        $domain_id = 0;

        foreach ($this->settings['domains'] as $domain) {
            if ($domain['id'] > $domain_id)
                $domain_id = $domain['id'];
        }

        return $domain_id + 1;
    }

    function saved_admin_notice()
    {
        if (str_true($this->get_setting('enabled'))) {
            ?>
            <div class="notice notice-success is-dismissible">
                <p><?php _e('Simple LDAP Login settings have been saved.', $this->prefix); ?></p>
            </div>
            <?php
        } else {
            ?>
            <div class="notice notice-error is-dismissible">
                <p><?php _e('Simple LDAP Login is disabled.', $this->prefix); ?></p>
            </div>
            <?php
        }
    }

    function authenticate($user, $username, $password, $sso_auth = FALSE)
    {
        // If previous authentication succeeded, respect that
        if (is_a($user, 'WP_User')) {
            return $user;
        }

        // Determine if user a local admin
        $local_admin = false;
        $user_obj = get_user_by('login', $username);
        if (user_can($user_obj, 'update_core')) {
            $local_admin = true;
        }

        $local_admin = apply_filters('sll_force_ldap', $local_admin);
        $password = stripslashes($password);

        // To force LDAP authentication, the filter should return boolean false

        if (empty($username) || empty($password)) {
            $error = new WP_Error();

            if (empty($username)) {
                $error->add('empty_username', __('<strong>ERROR</strong>: The username field is empty.'));
            }

            if (empty($password)) {
                $error->add('empty_password', __('<strong>ERROR</strong>: The password field is empty.'));
            }

            return $error;
        }

        // If high security mode is enabled, remove default WP authentication hook
        if (apply_filters('sll_remove_default_authentication_hook', str_true($this->get_setting('high_security')) && !$local_admin)) {
            remove_filter('authenticate', 'wp_authenticate_username_password', 20, 3);
        }

        // Sweet, let's try to authenticate our user and pass against LDAP
        $auth_result = $this->ldap_auth($username, $password, trim($this->get_setting('directory')), $sso_auth);

        if ($auth_result) {
            // Authenticated, does user have required groups, if any?
            if ($this->user_has_groups($username, trim($this->get_setting('directory')))) {

                $user = get_user_by('login', $username);

                if (!$user || (strtolower($user->user_login) !== strtolower($username))) {
                    if (!str_true($this->get_setting('create_users'))) {
                        do_action('wp_login_failed', $username);
                        return $this->ldap_auth_error('invalid_username', __('<strong>Simple LDAP Login Error</strong>: LDAP credentials are correct, but there is no matching WordPress user and user creation is not enabled.'));
                    }

                    $new_user = wp_insert_user($this->get_user_data($username, trim($this->get_setting('directory'))));

                    if (!is_wp_error($new_user)) {
                        // Add user meta data
                        $user_meta_data = $this->get_user_meta_data($username, trim($this->get_setting('directory')));

                        // Check, if empty to prevent login failures
                        if ($user_meta_data !== false) {
                            foreach ($user_meta_data as $meta_key => $meta_value) {
                                add_user_meta($new_user, $this->get_meta_key_ldap($meta_key), $meta_value);
                                add_user_meta($new_user, $this->get_meta_key_wp($meta_key), $meta_value);
                            }
                        }

                        // Successful Login
                        $new_user = new WP_User($new_user);
                        do_action_ref_array($this->prefix . 'auth_success', array($new_user));

                        return $new_user;
                    } else {
                        do_action('wp_login_failed', $username);
                        return $this->ldap_auth_error("{$this->prefix}login_error", __('<strong>Simple LDAP Login Error</strong>: LDAP credentials are correct and user creation is allowed but an error occurred creating the user in WordPress. Actual error: ' . $new_user->get_error_message()));
                    }
                } else {

                    // update user meta data
                    $user_meta_data = $this->get_user_meta_data($username, trim($this->get_setting('directory')));

                    // prevent error
                    if ($user_meta_data !== false) {
                        foreach ($user_meta_data as $meta_key => $meta_value) {
                            $actual = get_user_meta($user->ID, $this->get_meta_key_ldap($meta_key));

                            // new value: change the meta attributes
                            if (empty($actual) || $actual[0] !== $meta_value) {
                                update_user_meta($user->ID, $this->get_meta_key_ldap($meta_key), $meta_value);
                                update_user_meta($user->ID, $this->get_meta_key_wp($meta_key), $meta_value);
                            }
                        }
                    }

                    return new WP_User($user->ID);
                }
            } else {
                return $this->ldap_auth_error("{$this->prefix}login_error", __('<strong>Simple LDAP Login Error</strong>: Your LDAP credentials are correct, but you are not in an authorized LDAP group.'));
            }
        } elseif (str_true($this->get_setting('high_security'))) {
            return $this->ldap_auth_error('invalid_username', __('<strong>Simple LDAP Login</strong>: Simple LDAP Login could not authenticate your credentials. The security settings do not permit trying the WordPress user database as a fallback.'));
        }

        do_action($this->prefix . 'auth_failure');
        return false;
    }

    function get_domain_username($username)
    {
        // Format username with domain prefix, if login_domain is set
        $login_domain = trim($this->get_setting('login_domain'));

        if (!empty($login_domain)) {
            return $login_domain . '\\' . $username;
        }

        return $username;
    }

    function ldap_auth($username, $password, $directory, $sso_auth)
    {
        $result = false;

        if ($directory == "ad") {
            $result = $this->adldap->authenticate($this->get_domain_username($username), $password, FALSE, $sso_auth);
        } elseif ($directory == "ol") {
            // TODO - implement SSO to others directories 
            $this->ldap = ldap_connect(join(' ', (array)$this->get_setting('domain_controllers')), (int)$this->get_setting('ldap_port'));
            ldap_set_option($this->ldap, LDAP_OPT_PROTOCOL_VERSION, (int)$this->get_setting('ldap_version'));
            if (str_true($this->get_setting('use_tls'))) {
                ldap_start_tls($this->ldap);
            }
            // TODO - username should be DN escaped - rfc4514
            $dn = trim($this->get_setting('ol_login')) . '=' . $username . ',' . trim($this->get_setting('base_dn'));
            if (str_true($this->get_setting('search_sub_ous'))) {
                // search for user's DN in the base DN and below
                $filter = sprintf('(%s=%s)', trim($this->get_setting('ol_login')), $this->esc_ldap_filter_val($username));
                $sr = @ldap_search($this->ldap, $this->get_setting('base_dn'), $filter, array('cn'));
                if ($sr !== FALSE) {
                    $info = @ldap_get_entries($this->ldap, $sr);
                    if ($info !== FALSE && $info['count'] > 0) {
                        $dn = $info[0]['dn'];
                    }
                }
            }
            $ldapbind = @ldap_bind($this->ldap, $dn, $password);
            $this->dn = $dn;
            $result = $ldapbind;
        }

        return apply_filters($this->prefix . 'ldap_auth', $result);
    }

    /**
     * Prevent modification of the error message by other authenticate hooks
     * before it is shown to the user
     *
     * @param string $code
     * @param string $message
     * @return WP_Error
     */
    function ldap_auth_error($code, $message)
    {
        remove_all_filters('authenticate');
        return new WP_Error($code, $message);
    }

    function user_has_groups($username = false, $directory)
    {
        $result = false;
        $groups = (array)$this->get_setting('groups');
        $groups = array_filter($groups);

        if (!$username) {
            return $result;
        }
        if (count($groups) == 0) {
            return true;
        }

        if ($directory == "ad") {
            foreach ($groups as $gp) {
                if ($this->adldap->user_ingroup($username, $gp)) {
                    $result = true;
                    break;
                }
            }
        } elseif ($directory == "ol") {
            if ($this->ldap === false)
                return false;

            $group_base_dn = $this->get_setting('group_base_dn') !== false ? trim($this->get_setting('group_base_dn')) : trim($this->get_setting('base_dn'));
            $ol_filter = sprintf('(|(&(objectClass=groupOfUniqueNames)(uniquemember=%s))(&(objectClass=groupOfNames)(member=%s))(%s=%s))', $this->dn, $this->dn, trim($this->get_setting('group_uid')), $this->esc_ldap_filter_val($username));
            $result = ldap_search($this->ldap, $group_base_dn, $ol_filter, array($this->get_setting('ol_group')));
            $ldapgroups = ldap_get_entries($this->ldap, $result);


            // Ok, we should have the user, all the info, including which groups he is a member of.
            // Let's make sure he's in the right group before proceeding.
            $user_groups = array();
            for ($i = 0; $i < $ldapgroups['count']; $i++) {
                $user_groups[] = is_array($ldapgroups[$i][$this->get_setting('ol_group')]) ? $ldapgroups[$i][$this->get_setting('ol_group')][0] : $ldapgroups[$i][$this->get_setting('ol_group')];
            }

            $result = (bool)(count(array_intersect($user_groups, $groups)) > 0);
        }

        return apply_filters($this->prefix . 'user_has_groups', $result);
    }

    function get_user_data($username, $directory)
    {
        $user_data = array(
            'user_pass' => md5(microtime()),
            'user_login' => $username,
            'user_nicename' => '',
            'user_email' => '',
            'display_name' => '',
            'first_name' => '',
            'last_name' => '',
            'user_url' => '',
            'role' => $this->get_setting('role')
        );

        if ($directory == "ad") {
            $userinfo = $this->adldap->user_info($username, array(
                trim($this->get_setting('ol_login')),
                trim($this->get_setting('user_last_name_attribute')),
                trim($this->get_setting('user_first_name_attribute')),
                trim($this->get_setting('user_email_attribute')),
                trim($this->get_setting('user_url_attribute'))
            ));
            $userinfo = $userinfo[0];
        } elseif ($directory == "ol") {
            if ($this->ldap == null) {
                return false;
            }

            $attributes = array(
                trim($this->get_setting('ol_login')),
                trim($this->get_setting('user_last_name_attribute')),
                trim($this->get_setting('user_first_name_attribute')),
                trim($this->get_setting('user_email_attribute')),
                trim($this->get_setting('user_url_attribute'))
            );

            $ol_filter = sprintf('(%s=%s)', trim($this->get_setting('ol_login')), $this->esc_ldap_filter_val($username));
            $result = ldap_search($this->ldap, $this->get_setting('base_dn'), $ol_filter, $attributes);
            $userinfo = ldap_get_entries($this->ldap, $result);

            if ($userinfo['count'] == 1) {
                $userinfo = $userinfo[0];
            }
        } else {
            return false;
        }

        if (is_array($userinfo)) {
//            print_r($userinfo);
            $user_data['user_nicename'] = strtolower($userinfo[trim($this->get_setting('ol_login'))][0]);
            $user_data['user_email'] = array_key_exists(trim($this->get_setting('user_email_attribute')), $userinfo) ? $userinfo[trim($this->get_setting('user_email_attribute'))][0] : "";
            $user_data['display_name'] = $userinfo[trim($this->get_setting('user_first_name_attribute'))][0] . ' ' . $userinfo[trim($this->get_setting('user_last_name_attribute'))][0];
            $user_data['first_name'] = $userinfo[trim($this->get_setting('user_first_name_attribute'))][0];
            $user_data['last_name'] = $userinfo[trim($this->get_setting('user_last_name_attribute'))][0];
            $user_data['user_url'] = array_key_exists(trim($this->get_setting('user_url_attribute')), $userinfo) ? $userinfo[trim($this->get_setting('user_url_attribute'))][0] : "";
        }

        return apply_filters($this->prefix . 'user_data', $user_data);
    }

    function get_user_meta_data($username, $directory)
    {
        $meta_data_list = $this->get_setting('user_meta_data');
        if (empty($meta_data_list)) {
            return false;
        }

        $attributes = array();
        foreach ($meta_data_list as $attr) {
            $attributes[] = $attr[0];
        }

        if ($directory == "ad") {
            $userinfo = $this->adldap->user_info($username, $attributes);
        } elseif ($directory == "ol") {
            if ($this->ldap == null) {
                return false;
            }

            $ol_filter = sprintf('(%s=%s)', trim($this->get_setting('ol_login')), $this->esc_ldap_filter_val($username));
            $result = ldap_search($this->ldap, $this->get_setting('base_dn'), $ol_filter, $attributes);
            $userinfo = ldap_get_entries($this->ldap, $result);
        } else {
            return false;
        }

        if ($userinfo['count'] == 1) {
            $userinfo = $userinfo[0];
        } else {
            return false;
        }

        $user_meta_data = array();
        foreach ($meta_data_list as $attr) {
            $user_meta_data[$attr[1]] = $this->meta_data_filter(isset($userinfo[$attr[0]]) ? $userinfo[$attr[0]][0] : "", isset($attr[2]) ? $attr[2] : "string");
        }

        return apply_filters($this->prefix . 'user_meta_data', $user_meta_data);
    }

    function meta_data_filter($value, $type)
    {
        if ($type === "number") {
            return preg_replace("/[^0-9]/", "", $value);
        }
        return $value;
    }

    function get_meta_key_ldap($meta_key)
    {
        return "{$meta_key}_{$this->get_setting('meta_data_suffix_ldap')}";
    }

    function get_meta_key_wp($meta_key)
    {
        return "{$meta_key}_{$this->get_setting('meta_data_suffix_wp')}";
    }

    /**
     * Returns whether this plugin is currently network activated
     */
    function is_network_version()
    {
        if ($this->network_version !== null) {
            return $this->network_version;
        }

        if (!function_exists('is_plugin_active_for_network')) {
            require_once(ABSPATH . '/wp-admin/includes/plugin.php');
        }

        if (is_plugin_active_for_network(plugin_basename(__FILE__))) {
            $this->network_version = true;
        } else {
            $this->network_version = false;
        }
        return $this->network_version;
    }

    /**
     * clean ldap filter values
     */
    function esc_ldap_filter_val($str = '')
    {
        if (function_exists('ldap_escape')) {
            return ldap_escape($str, '', LDAP_ESCAPE_FILTER);
        } else {
            $metaChars = array("\\", "\00", "(", ")", "*");
            $quotedMetaChars = array("\\0x5x", "\\0x00", "\\0x28", "\\0x29", "\\0x2a");
            $str = str_replace($metaChars, $quotedMetaChars, $str);
            return $str;
        }
    }

    function is_sso_enabled()
    {
        return str_true($this->get_setting('sso_enabled'));
    }

    function is_sso_configuration_ok()
    {
        return isset($_SERVER['REMOTE_USER']) && !empty($_SERVER['REMOTE_USER']);
    }

    function get_sso_logged_user()
    {
        return $this->is_sso_configuration_ok() ? $_SERVER['REMOTE_USER'] : FALSE;
    }

    function sso_search_user_bind_test()
    {
        $directory = $this->get_setting('directory');
        if ($directory == "ad") {
            return $this->adldap->authenticate($this->get_domain_username($this->get_setting('sso_search_user')), $this->get_sso_search_user_pass());
        } elseif ($directory == "ol") {
            // TODO - Implement bind test to other directories
        } else {
            return FALSE;
        }
    }

    private function get_sso_search_user_pass()
    {
        $cryptPass = explode(";", $this->get_setting('sso_search_user_password'));
        if (count($cryptPass) != 2) {
            return ""; // wrong pass
        }
        return openssl_decrypt($cryptPass[0], self::$openssl_method, $this->get_openssl_pass(), 0, hex2bin($cryptPass[1]));
    }

}

if (!function_exists('str_true')) {

    /**
     * Evaluates natural language strings to boolean equivalent
     *
     * Used primarily for handling boolean text provided in shopp() tag options.
     * All values defined as true will return true, anything else is false.
     *
     * Boolean values will be passed through.
     *
     * Replaces the 1.0-1.1 value_is_true()
     *
     * @author Jonathan Davis
     * @since 1.2
     *
     * @param string $string The natural language value
     * @param array $istrue A list strings that are true
     * @return boolean The boolean value of the provided text
     * */
    function str_true($string, $istrue = array('yes', 'y', 'true', '1', 'on', 'open'))
    {
        if (is_array($string)) {
            return false;
        }
        if (is_bool($string)) {
            return $string;
        }
        return in_array(strtolower($string), $istrue);
    }

}

$CustomLDAPLogin = CustomLDAPLogin::getInstance();

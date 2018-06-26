<?php
global $CustomLDAPLogin;

if (isset($_GET['tab'])) {
    $active_tab = stripslashes_deep($_GET['tab']);
} else {
    $active_tab = 'domains';
}

?>
<div class="wrap" xmlns="http://www.w3.org/1999/html">

    <?php if($active_tab != "domains-edit"):?>
    <div id="icon-themes" class="icon32"></div>
    <h2>Simple LDAP Login Settings</h2>

    <h2 class="nav-tab-wrapper">
        <a href="<?php echo esc_url(add_query_arg(array('tab' => 'domains'), $_SERVER['REQUEST_URI'])); ?>"
           class="nav-tab <?php echo $active_tab == 'domains' ? 'nav-tab-active' : ''; ?>">Domains</a>
        <a href="<?php echo esc_url(add_query_arg(array('tab' => 'user'), $_SERVER['REQUEST_URI'])); ?>"
           class="nav-tab <?php echo $active_tab == 'user' ? 'nav-tab-active' : ''; ?>">User</a>
        <a href="<?php echo esc_url(add_query_arg(array('tab' => 'sso'), $_SERVER['REQUEST_URI'])); ?>"
           class="nav-tab <?php echo $active_tab == 'sso' ? 'nav-tab-active' : ''; ?>">SSO</a>
        <a href="<?php echo esc_url(add_query_arg(array('tab' => 'help'), $_SERVER['REQUEST_URI'])); ?>"
           class="nav-tab <?php echo $active_tab == 'help' ? 'nav-tab-active' : ''; ?>">Help</a>
    </h2>
    <?php endif;?>
    <?php if ($active_tab == "domains" || $active_tab == "domains-edit"): ?>
        <?php if($active_tab == "domains"):?>
        <form method="post" action="<?php echo str_replace('%7E', '~', $_SERVER['REQUEST_URI']); ?>">
            <?php wp_nonce_field('update_domains', 'save_the_cll'); ?>
            <input type="hidden" value="update_domains" name="csl_action"/>
            <div class="tablenav">
                <div class="alignleft">
                    <input type="submit" class="button-secondary delete" name="deleteit" value="Delete"/>
                    <input type="submit" class="button-secondary delete" name="updateit" value="Update"/>
                </div>
                <br class="clear"/>
            </div>
            <table class="widefat">
                <thead>
                <tr class="thead">
                    <th scope="col"></th>
                    <th scope="col">Name</th>
                    <th scope="col">AccountSuffix</th>
                    <th scope="col">Domain Controller</th>
                    <th scope="col">Create User</th>
                    <th scope="col">Enabled</th>
                </tr>
                </thead>
                <tbody>
                <?php
                $domains = $this->get_setting('domains');
                foreach ($domains as $domain) {
                    ?>
                    <tr class="alternate" id="group-<?php echo $domain['id'] ?>">
                        <th class="check-column">
                            <label>
                                <input type="checkbox" value="<?php echo $domain['id'] ?>" name="delete[]"/>
                            </label>
                        </th>
                        <td>
                            <?php echo $domain['name'] ?>
                        </td>
                        <td>
                            <?php echo $domain['account_suffix'] ?>
                        </td>
                        <td>
                            <?php echo $domain['base_dn'] ?>
                        </td>
                        <td>
                            <?php echo $domain['create_users'] ? 'true' : 'false';  ?>
                        </td>
                        <td>
                            <label>
                                <input type="checkbox" value="<?php $domain['id'] ?>" name="enable[]" <?php if($domain['enabled'] == 'true') echo "checked='checked'"; ?> />
                            </label>
                        </td>
                    </tr>
                    <?php
                }
                ?>
                </tbody>
            </table>
            <div class="tablenav">
                <div class="alignleft">
                    <input type="submit" class="button-secondary delete" name="deleteit" value="Delete"/>
                    <input type="submit" class="button-secondary delete" name="updateit" value="Update"/>
                </div>
                <br class="clear"/>
            </div>
        </form>
        <?php endif;?>
        <div class="postbox">
            <h2 style="margin-left: 17px"><?php echo $active_tab == 'domains-edit' ? 'Edit Domain' : 'Add Domain'; ?></h2>
            <div class="inside">
                <form method="post" action="<?php echo str_replace('%7E', '~', $_SERVER['REQUEST_URI']); ?>">
                    <?php
                    wp_nonce_field('add_domain', 'save_the_cll');
                    $domain_to_edit =$CustomLDAPLogin->edit_domain;
                    ?>
                    <table>
                        <tbody>
                        <tr>
                            <td>
                                <div class="postbox" style="margin-bottom: 0px">
                                    <div class="inside" >
                                        <table class="form-table">
                                            <thead>
                                            <tr>
                                                <th style="padding: 0px" colspan="2">
                                                    <h1>Required</h1>
                                                    <small>These are the most basic settings you must configure. Without these, you won't be able to use Simple LDAP Login.</small>
                                                    <hr/>
                                                </th>
                                            </tr>
                                            </thead>
                                            <tbody>
                                            <tr>
                                                <th scope="row" valign="top">Domain Name</th>
                                                <td>
                                                    <input type="text"
                                                           name="<?php echo esc_attr($this->get_field_name('name')); ?>"
                                                           value="<?php echo htmlspecialchars($domain_to_edit['name']); ?>"/>
                                                </td>
                                            </tr>
                                            <tr>
                                                <th scope="row" valign="top">Account Suffix</th>
                                                <td>
                                                    <input type="text"
                                                           name="<?php echo esc_attr($this->get_field_name('account_suffix')); ?>"
                                                           value="<?php echo htmlspecialchars($domain_to_edit['account_suffix']); ?>"/><br/>
                                                    <small>Often the suffix of your e-mail address. Example: @gmail.com</small>
                                                </td>
                                            </tr>
                                            <tr>
                                                <th scope="row" valign="top">Base DN</th>
                                                <td>
                                                    <input type="text"
                                                           name="<?php echo esc_attr($this->get_field_name('base_dn')); ?>"
                                                           value="<?php echo esc_attr($domain_to_edit['base_dn']); ?>"/>
                                                    <br/>
                                                    <small>Example: For subdomain.domain.suffix, use
                                                    DC=subdomain,DC=domain,DC=suffix.
                                                        In most cases you should not specify an ou here.</small>
                                                </td>
                                            </tr>
                                            <tr>
                                                <th scope="row" valign="top">Domain Controller(s)</th>
                                                <td>
                                                    <input type="text"
                                                           name="<?php echo esc_attr($this->get_field_name('domain_controllers', 'array')); ?>"
                                                           value="<?php echo esc_attr(join(';', (array)$domain_to_edit['domain_controllers'])); ?>"/>
                                                    <small><br/>Separate with semi-colons.z</small>
                                                </td>
                                            </tr>
                                            <tr>
                                                <th scope="row" valign="top">LDAP Directory</th>
                                                <td>
                                                    <label><input type="radio"
                                                                  name="<?php echo esc_attr($this->get_field_name('directory')); ?>"
                                                                  value="ad" <?php if ($domain_to_edit['directory'] == "ad") echo "checked='checked'"; ?> />
                                                        Active Directory</label><br/>
                                                    <label><input type="radio"
                                                                  name="<?php echo esc_attr($this->get_field_name('directory')); ?>"
                                                                  value="ol" <?php if ($domain_to_edit['directory'] == "ol") echo "checked='checked'"; ?> />
                                                        Open LDAP (and etc)</label>
                                                </td>
                                            </tr>
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </td>
                            <td rowspan="2" valign="top" height="100%">
                                <div class="postbox" height="100%">
                                    <div class="inside" height="100%">
                                        <table class="form-table">
                                            <thead>
                                            <tr>
                                                <th style="padding: 0px" colspan="2">
                                                    <h1>Extraordinary</h1>
                                                    <small>Most users should leave these alone.</small>
                                                    <hr/>
                                                </th>

                                            </tr>
                                            </thead>
                                            <tbody>
                                            <tr>
                                                <th scope="row" valign="top">Group Base DN (optional)</th>
                                                <td>
                                                    <input type="text"
                                                           name="<?php echo esc_attr($this->get_field_name('group_base_dn')); ?>"
                                                           value="<?php echo esc_attr($domain_to_edit['group_base_dn']); ?>"/>
                                                    <br/>
                                                    <small>If you need to specify a different Base DN for group searches.
                                                    Example: For subdomain.domain.suffix, use
                                                        ou=groups,DC=subdomain,DC=domain,DC=suffix.</small>
                                                </td>
                                            </tr>
                                            <tr>
                                                <th scope="row" valign="top">LDAP Login Attribute</th>
                                                <td>
                                                    <input type="text"
                                                           name="<?php echo esc_attr($this->get_field_name('ol_login')); ?>"
                                                           value="<?php echo esc_attr($domain_to_edit['ol_login']); ?>"/>
                                                    <br/>
                                                    <small>Default: <b>uid</b>;</small>
                                                </td>
                                            </tr>
                                            <tr>
                                                <th scope="row" valign="top">LDAP Group Attribute</th>
                                                <td>
                                                    <input type="text"
                                                           name="<?php echo esc_attr($this->get_field_name('ol_group')); ?>"
                                                           value="<?php echo esc_attr($domain_to_edit['ol_group']); ?>"/>
                                                    <br/>
                                                    <small>In case your installation uses something other than <b>cn</b>;</small>
                                                </td>
                                            </tr>
                                            <tr>
                                                <th scope="row" valign="top">Use TLS</th>
                                                <td>
                                                    <input type="hidden"
                                                           name="<?php echo esc_attr($this->get_field_name('use_tls')); ?>"
                                                           value="false"/>
                                                    <label><input type="checkbox"
                                                                  name="<?php echo esc_attr($this->get_field_name('use_tls')); ?>"
                                                                  value="true" <?php if (str_true($domain_to_edit['use_tls'])) echo "checked='checked'"; ?> />
                                                        Transport Layer Security.<br/>
                                                        <small>This feature is beta, very
                                                            beta.</small></label>
                                                </td>
                                            </tr>
                                            <tr>
                                                <th scope="row" valign="top">LDAP Port</th>
                                                <td>
                                                    <input type="text"
                                                           name="<?php echo esc_attr($this->get_field_name('ldap_port')); ?>"
                                                           value="<?php echo esc_attr($domain_to_edit['ldap_port']); ?>"/><br/>
                                                    <small>This is usually 389.</small>
                                                </td>
                                            </tr>
                                            <tr>
                                                <th scope="row" valign="top">LDAP Version</th>
                                                <td>
                                                    <input type="text"
                                                           name="<?php echo esc_attr($this->get_field_name('ldap_version')); ?>"
                                                           value="<?php echo esc_attr($domain_to_edit['ldap_version']); ?>"/><br/>
                                                    <small>Only applies to Open LDAP. Typically 3.</small>
                                                </td>
                                            </tr>
                                            <tr>
                                                <th scope="row" valign="top">Search Sub OUs</th>
                                                <td>
                                                    <input type="hidden"
                                                           name="<?php echo esc_attr($this->get_field_name('search_sub_ous')); ?>"
                                                           value="false"/>
                                                    <label><input type="checkbox"
                                                                  name="<?php echo esc_attr($this->get_field_name('search_sub_ous')); ?>"
                                                                  value="true" <?php if (str_true($domain_to_edit['search_sub_ous'])) echo "checked='checked'"; ?> />
                                                        Also search sub-OUs of Base DN.<br>
                                                        <small>For example, if the base DN is
                                                        "ou=People,dc=example,dc=com", also search
                                                        "ou=Staff,ou=People,dc=example,dc=com for
                                                        uid=<i>username</i></small></label><br/>
                                                </td>
                                            </tr>
                                            <tr>
                                                <th scope="row" valign="top">Login Domain</th>
                                                <td>
                                                    <input type="text"
                                                           name="<?php echo esc_attr($this->get_field_name('login_domain')); ?>"
                                                           value="<?php echo esc_attr($domain_to_edit['login_domain']); ?>"/><br/>
                                                    <small>prefixes login names with this domain, f.i. mydomain\username</small>
                                                </td>
                                            </tr>
                                            </tbody>
                                        </table>
                                        <br/>
                                    </div>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <td>
                                <div class="postbox">
                                    <div class="inside">
                                        <table class="form-table">
                                            <thead>
                                            <tr>
                                                <th style="padding: 0px" colspan="2">
                                                    <h1>Typical</h1>
                                                    <small>These settings give you finer control over how logins work.</small>
                                                    <hr/>
                                                </th>
                                            <tr>
                                            </thead>
                                            <tbody>
                                            <tr>
                                                <th scope="row" valign="top">Required Groups</th>
                                                <td>
                                                    <input type="text"
                                                           name="<?php echo esc_attr($this->get_field_name('groups', 'array')); ?>"
                                                           value="<?php echo esc_attr(join(';', (array)$domain_to_edit['groups'])); ?>"/><br/>
                                                    <small>The groups, if any, that authenticating LDAP users must
                                                        belong to.<br/>
                                                        Empty means no group required. Separate with semi-colons.
                                                    </small>
                                                </td>
                                            </tr>
                                            <tr>
                                                <th scope="row" valign="top">User Creations</th>
                                                <td>
                                                    <input type="hidden"
                                                           name="<?php echo esc_attr($this->get_field_name('create_users')); ?>"
                                                           value="false"/>
                                                    <label><input type="checkbox"
                                                                  name="<?php echo esc_attr($this->get_field_name('create_users')); ?>"
                                                                  value="true" <?php if (str_true($domain_to_edit['create_users'])) echo "checked='checked'"; ?> />
                                                        Create WordPress user for authenticated LDAP login with
                                                        appropriate
                                                        roles.</label><br/>
                                                </td>
                                            </tr>
                                            <tr>
                                                <th scope="row" valign="top">New User Role</th>
                                                <td>
                                                    <select name="<?php echo esc_attr($this->get_field_name('role')); ?>">
                                                        <?php wp_dropdown_roles(strtolower($domain_to_edit['role'])); ?>
                                                    </select>
                                                </td>
                                            </tr>
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </td>
                        </tr>

                        </tbody>
                    </table>
                    <p><input class="button-primary" type="submit" value="<?php echo $active_tab == 'domains-edit' ? 'Update domain settings' : 'Add domain'; ?>"/></p>
                </form>
            </div>
        </div>
    <?php else: ?>
        <form method="post" action="<?php echo str_replace('%7E', '~', $_SERVER['REQUEST_URI']); ?>">
            <?php wp_nonce_field('save_sll_settings', 'save_the_sll'); ?>

            <?php if ($active_tab == "sso"): ?>
                <h3>Typical</h3>
                <p>These are the basic settings for the Single Sign-on (SSO) between LDAP and Wordpress. For this
                    functionality, you must configure the Apache to use an authentication method in the Wordpress
                    Directory, as the auth_ntlm_winbind (for NTLM) or the auth_kerb (for Kerberos).</p>
                <table class="form-table" style="margin-bottom: 20px;">
                    <tbody>
                    <tr>
                        <th scope="row" valign="top">Server Status</th>
                        <td>
                            <?php if (!$this->is_sso_configuration_ok()) { ?>
                                <p style="color: red">Configuration Not Found.</p>
                            <?php } else { ?>
                                <p style="color: green">Configuration Found. You are logged in as
                                    <b><?php echo $this->get_sso_logged_user(); ?></b>.</p>
                            <?php } ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row" valign="top">Enable SSO</th>
                        <td>
                            <input type="hidden" name="<?php echo esc_attr($this->get_field_name('sso_enabled')); ?>"
                                   value="false"/>
                            <label><input type="checkbox"
                                          name="<?php echo esc_attr($this->get_field_name('sso_enabled')); ?>"
                                          value="true" <?php if (str_true($this->get_setting('sso_enabled'))) echo "checked='checked'"; ?> />
                                Enable SSO between LDAP and Wordpress.</label><br/>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row" valign="top">Search User</th>
                        <td>
                            <input type="text" name="<?php echo esc_attr($this->get_field_name('sso_search_user')); ?>"
                                   value="<?php echo esc_attr($CustomLDAPLogin->get_setting('sso_search_user')); ?>"/>
                            <br/>
                            User with permission to make search of others users into LDAP.
                        </td>
                    </tr>
                    <tr>
                        <th scope="row" valign="top">Search User Password</th>
                        <td>
                            <input type="password"
                                   name="<?php echo esc_attr($this->get_field_name('sso_search_user_password', 'password')); ?>"
                                   value=""/>
                            <br/>
                            User password.
                        </td>
                    </tr>
                    <tr>
                        <th scope="row" valign="top">Bind Search User Status</th>
                        <td>
                            <?php if (!$this->is_sso_enabled()) { ?>
                                <p>SSO disabled.</p>
                                <?php
                            } else {
                                $bind_test = $this->sso_search_user_bind_test();
                                if ($bind_test) {
                                    ?>
                                    <p style="color: green">Bind OK for search user
                                        '<b><?php echo $CustomLDAPLogin->get_setting('sso_search_user'); ?></b>'.</p>
                                    <?php
                                } else {
                                    ?>
                                    <p style="color: red">Bind failure for search user
                                        '<b><?php echo $CustomLDAPLogin->get_setting('sso_search_user'); ?></b>'.</p>
                                    <?php
                                }
                            }
                            ?>
                        </td>
                    </tr>
                    </tbody>
                </table>
                <p><input class="button-primary" type="submit" value="Save Settings"/></p>
            <?php elseif ($active_tab == "user"): ?>
                <h3>User Data</h3>
                <p>These settings give you control over which LDAP attributes are used for user creation.</p>
                <table class="form-table" style="margin-bottom: 20px;">
                    <tbody>
                    <tr>
                        <th scope="row" valign="top">First name</th>
                        <td>
                            <input type="text"
                                   name="<?php echo esc_attr($this->get_field_name('user_first_name_attribute')); ?>"
                                   value="<?php echo esc_attr($CustomLDAPLogin->get_setting('user_first_name_attribute')); ?>"/>
                            <br/>
                            The LDAP attribute for the first name.
                        </td>
                    </tr>
                    <tr>
                        <th scope="row" valign="top">Last name</th>
                        <td>
                            <input type="text"
                                   name="<?php echo esc_attr($this->get_field_name('user_last_name_attribute')); ?>"
                                   value="<?php echo esc_attr($CustomLDAPLogin->get_setting('user_last_name_attribute')); ?>"/>
                            <br/>
                            The LDAP attribute for the last name.
                        </td>
                    </tr>
                    <tr>
                        <th scope="row" valign="top">Email</th>
                        <td>
                            <input type="text"
                                   name="<?php echo esc_attr($this->get_field_name('user_email_attribute')); ?>"
                                   value="<?php echo esc_attr($CustomLDAPLogin->get_setting('user_email_attribute')); ?>"/>
                            <br/>
                            The LDAP attribute for the email.
                        </td>
                    </tr>
                    <tr>
                        <th scope="row" valign="top">Website</th>
                        <td>
                            <input type="text"
                                   name="<?php echo esc_attr($this->get_field_name('user_url_attribute')); ?>"
                                   value="<?php echo esc_attr($CustomLDAPLogin->get_setting('user_url_attribute')); ?>"/>
                            <br/>
                            The LDAP attribute for the website.
                        </td>
                    </tr>
                    </tbody>
                </table>
                <hr/>
                <h3>Additional user data</h3>
                <p>Additional user data can be stored as user meta data. You can specify the LDAP
                    attributes and the associated wordpress meta keys in the format <i>&lt;ldap_attribute_name&gt;:&lt;wordpress_meta_key&gt;:&lt;type&gt;</i>.
                    Multiple attributes can be given on separate lines.
                    <b>Keep in your mind that the final <i>wordpress_meta_key</i> will be two meta keys, using the
                        suffixes below, like,
                        <i>wordpress_meta_key_<?php echo $CustomLDAPLogin->get_setting('meta_data_suffix_ldap'); ?></i>
                        and
                        <i>wordpress_meta_key_<?php echo $CustomLDAPLogin->get_setting('meta_data_suffix_wp'); ?></i>.</b>
                </p>
                <p> Example:<br/><i>phone:user_phone_number:number</i><br/><i>address:user_home_address:string</i></p>
                <table class="form-table" style="margin-bottom: 20px;">
                    <tbody>
                    <tr>
                        <th scope="row" valign="top">Meta data</th>
                        <td>
                                <textarea cols="50"
                                          name="<?php echo esc_attr($this->get_field_name('user_meta_data')); ?>"><?php
                                    echo esc_html(join("\n", array_map(function ($attr) {
                                        return join(':', $attr);
                                    }, $CustomLDAPLogin->get_setting('user_meta_data'))));
                                    ?></textarea>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row" valign="top">Suffix data LDAP</th>
                        <td>
                            <input type="text"
                                   name="<?php echo esc_attr($this->get_field_name('meta_data_suffix_ldap')); ?>"
                                   value="<?php echo esc_attr($CustomLDAPLogin->get_setting('meta_data_suffix_ldap')); ?>"/>
                            <br/>
                            Suffix for the data obtained in the LDAP.
                        </td>
                    </tr>
                    <tr>
                        <th scope="row" valign="top">Suffix data WP</th>
                        <td>
                            <input type="text"
                                   name="<?php echo esc_attr($this->get_field_name('meta_data_suffix_wp')); ?>"
                                   value="<?php echo esc_attr($CustomLDAPLogin->get_setting('meta_data_suffix_wp')); ?>"/>
                            <br/>
                            Suffix for the valid data (that can be displayed to the user).
                        </td>
                    </tr>
                    </tbody>
                </table>
                <p><input class="button-primary" type="submit" value="Save Settings"/></p>
            <?php else: ?>
                <h3>Help</h3>
                <p>Here's a brief primer on how to effectively use and test Simple LDAP Login.</p>
                <h4>SSO (Single Sign-on)</h4>
                <p>For this functionality, you must configure the Apache to use an authentication method in the
                    Wordpress Directory.</p>
                <ul>
                    <li>For Debian/Apache, you can follow the steps described <a target="_blank"
                                                                                 title="Configuring SSO in Debian/Apache"
                                                                                 href="https://github.com/MP-ES/simple-ldap-login/blob/master/ssoDebian.md">here</a>.
                    </li>
                    <li>For CentOS/Apache, you can follow the steps described <a target="_blank"
                                                                                 title="Configuring SSO in CentOS/Apache"
                                                                                 href="https://github.com/MP-ES/simple-ldap-login/blob/master/ssoCentOS.md">here</a>.
                    </li>
                </ul>
                <h4>Testing</h4>
                <p>The most effective way to test logins is to use two browsers. In other words, keep the WordPress
                    Dashboard open in Chrome, and use Firefox to try logging in. This will give you real time feedback
                    on your settings and prevent you from inadvertently locking yourself out.</p>
                <h4>Which raises the question, what happens if I get locked out?</h4>
                <p>If you accidentally lock yourself out, the easiest way to get back in is to rename
                    <strong><?php echo plugin_dir_path(__FILE__); ?></strong> to something else and then refresh.
                    WordPress will detect the change and disable Simple LDAP Login. You can then rename the folder back
                    to its previous name.</p>
            <?php endif; ?>
        </form>
    <?php endif; ?>
</div>

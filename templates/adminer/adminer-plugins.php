<?php
// Managed by lss (module adminer). Local changes are reported by "lss verify" and replaced on the next run; change
// LSS_ADMINER_SERVERS instead. Adminer loads this file from its own directory: the login form offers only the
// servers below, and a login to any other server, or with another driver, is refused.

/** Offers only the database servers lss configured (LSS_ADMINER_SERVERS) */
class AdminerLssServers extends Adminer\Plugin {
	/** @var array<string, array{server: string, driver: string}> */
	protected $servers = array(
{{ADMINER_SERVERS}}
	);

	function __construct() {
		if (isset($_POST['auth']['server'])) {
			$server = (string) $_POST['auth']['server'];
			$_POST['auth']['driver'] = isset($this->servers[$server]) ? $this->servers[$server]['driver'] : '';
		}
	}

	// Shown in Adminer's list of plugins; the parent class would look up a translation this plugin does not have.
	function description() {
		return 'Offers only the database servers lss configured';
	}

	function credentials() {
		$server = isset($this->servers[Adminer\SERVER]) ? $this->servers[Adminer\SERVER]['server'] : '';
		$username = isset($_GET['username']) ? (string) $_GET['username'] : '';
		return array($server, $username, Adminer\get_password());
	}

	function login($login, $password) {
		if (!isset($this->servers[Adminer\SERVER]) || $this->servers[Adminer\SERVER]['driver'] !== Adminer\DRIVER) {
			return false;
		}
	}

	function loginFormField($name, $heading, $value) {
		if ($name == 'driver') {
			return '';
		}
		if ($name == 'server') {
			return $heading . Adminer\html_select('auth[server]', array_keys($this->servers), Adminer\SERVER) . "\n";
		}
	}
}

return array(new AdminerLssServers());

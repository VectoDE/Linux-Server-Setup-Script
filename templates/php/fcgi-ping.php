<?php
// Used by "lss verify php": sends one FastCGI request for the pool's ping path over the pool's socket and prints the
// answer, which proves that PHP-FPM accepts and serves requests on that socket.
// Usage: php fcgi-ping.php SOCKET PATH

$socket = $argv[1] ?? '';
$path = $argv[2] ?? '';
$connection = @stream_socket_client('unix://' . $socket, $errno, $error, 5);
if ($connection === false) {
    fwrite(STDERR, "cannot connect to {$socket}: {$error}\n");
    exit(1);
}
stream_set_timeout($connection, 5);

// A record: version 1, type, request ID 1, content length, no padding.
function fcgi_record(int $type, string $content): string
{
    return pack('CCnnCx', 1, $type, 1, strlen($content), 0) . $content;
}

// A name-value pair with short (one byte) lengths; every name and value here is shorter than 128 bytes.
function fcgi_pair(string $name, string $value): string
{
    return chr(strlen($name)) . chr(strlen($value)) . $name . $value;
}

$params = '';
$values = [
    'GATEWAY_INTERFACE' => 'FastCGI/1.0',
    'REQUEST_METHOD' => 'GET',
    'SCRIPT_NAME' => $path,
    'SCRIPT_FILENAME' => $path,
    'REQUEST_URI' => $path,
    'QUERY_STRING' => '',
    'SERVER_PROTOCOL' => 'HTTP/1.1',
];
foreach ($values as $name => $value) {
    $params .= fcgi_pair($name, $value);
}

// BEGIN_REQUEST (role responder), PARAMS, end of PARAMS, end of STDIN.
fwrite($connection, fcgi_record(1, pack('nCx5', 1, 0)) . fcgi_record(4, $params) . fcgi_record(4, '')
    . fcgi_record(5, ''));

$output = '';
while (true) {
    $header = stream_get_contents($connection, 8);
    if ($header === false || strlen($header) < 8) {
        break;
    }
    $record = unpack('Cversion/Ctype/nid/nlength/Cpadding/Creserved', $header);
    $content = $record['length'] > 0 ? stream_get_contents($connection, $record['length']) : '';
    if ($record['padding'] > 0) {
        stream_get_contents($connection, $record['padding']);
    }
    if ($record['type'] === 6) {
        $output .= $content;
    }
    if ($record['type'] === 3) {
        break;
    }
}
fclose($connection);
echo $output;

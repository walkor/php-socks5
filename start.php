<?php
use \Workerman\Worker;
use \Workerman\WebServer;
use \Workerman\Connection\TcpConnection;
use \Workerman\Connection\AsyncTcpConnection;

// 自动加载类
require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/config.php';

define('STAGE_INIT', 0);
define('STAGE_AUTH', 1);
define('STAGE_ADDR', 2);
define('STAGE_UDP_ASSOC', 3);
define('STAGE_DNS', 4);
define('STAGE_CONNECTING', 5);
define('STAGE_STREAM', 6);
define('STAGE_DESTROYED', -1);

define('CMD_CONNECT', 1);
define('CMD_BIND', 2);
define('CMD_UDP_ASSOCIATE', 3);

define('ADDRTYPE_IPV4', 1);
define('ADDRTYPE_IPV6', 4);
define('ADDRTYPE_HOST', 3);

define('METHOD_NO_AUTH', 0);
define('METHOD_GSSAPI', 1);
define('METHOD_USER_PASS', 2);

$worker = new Worker('tcp://0.0.0.0:1080');
$worker->onConnect = function($connection)
{
    $connection->stage = STAGE_INIT;
};
$worker->onMessage = function($connection, $buffer)
{
    global $AUTH_ENABLED, $USERNAME, $PASSWORD;
    switch($connection->stage)
    {
        case STAGE_INIT:
            if ($AUTH_ENABLED)
            {
                $methodslen = ord($buffer[1]);
                $methods = array();
                for ($i = 0; $i < strlen($buffer)-3; $i++)
                {
                    array_push($methods, ord($buffer[$i+3]));
                }
                if (in_array(METHOD_USER_PASS, $methods))
                {
                    $connection->send("\x05\x02");
                    $connection->stage = STAGE_AUTH;
                    return;
                }
                echo "client does not support user/pass auth\n";
                $connection->send("\x05\xff");
                $connection->stage = STAGE_DESTROYED;
                $connection->close();
                return;
            }
            $connection->send("\x05\x00");
            $connection->stage = STAGE_ADDR;
            return;
        case STAGE_AUTH:
            $userlen = ord($buffer[1]);
            $user = substr($buffer, 2, $userlen);
            $passlen = ord($buffer[2 + $userlen]);
            $pass = substr($buffer, 3 + $userlen, $passlen);
            if ($user == $USERNAME && $pass == $PASSWORD)
            {
                $connection->send("\x05\x00");
                $connection->stage = STAGE_ADDR;
                return;
            }
            echo "auth failed\n";
            $connection->send("\x05\x01");
            $connection->stage = STAGE_DESTROYED;
            $connection->close();
            return;
        case STAGE_ADDR:
            $cmd = ord($buffer[1]);
            if($cmd != CMD_CONNECT)
            {
                echo "bad cmd $cmd\n";
                $connection->close();
                return;
            }
            $header_data = parse_socket5_header($buffer);
            if(!$header_data)
            {
                $connection->close();
                return;
            }
            $connection->stage = STAGE_CONNECTING;
            $remote_connection = new AsyncTcpConnection('tcp://'.$header_data[1].':'.$header_data[2]);
            $remote_connection->onConnect = function($remote_connection)use($connection)
            {
                $connection->state = STAGE_STREAM;
                $connection->send("\x05\x00\x00\x01\x00\x00\x00\x00\x10\x10");
                $connection->pipe($remote_connection);
                $remote_connection->pipe($connection);
            };
            $remote_connection->connect();
    }
};


function parse_socket5_header($buffer)
{
    $addr_type = ord($buffer[3]);
    switch($addr_type)
    {
        case ADDRTYPE_IPV4:
            if(strlen($buffer) < 10)
            {
                echo bin2hex($buffer)."\n";
                echo "buffer too short\n";
                return false;
            }
            $dest_addr = ord($buffer[4]).'.'.ord($buffer[5]).'.'.ord($buffer[6]).'.'.ord($buffer[7]);
            $port_data = unpack('n', substr($buffer, -2));
            $dest_port = $port_data[1];
            $header_length = 10;
            break;
        case ADDRTYPE_HOST:
            $addrlen = ord($buffer[4]);
            if(strlen($buffer) < $addrlen + 5)
            {
                echo $buffer."\n";
                echo bin2hex($buffer)."\n";
                echo "buffer too short\n";
                return false;
            }
            $dest_addr = substr($buffer, 5, $addrlen);
            $port_data = unpack('n', substr($buffer, -2));
            $dest_port = $port_data[1];
            $header_length = $addrlen + 7;
            break;
       case ADDRTYPE_IPV6:
            if(strlen($buffer) < 22)
            {
                echo "buffer too short\n";
                return false;
            }
            echo "todo ipv6\n";
            return false;
       default:
            echo "unsupported addrtype $addr_type\n";
            return false;
    }
    return array($addr_type, $dest_addr, $dest_port, $header_length);
}

// 如果不是在根目录启动，则运行runAll方法
if(!defined('GLOBAL_START'))
{
    Worker::runAll();
}

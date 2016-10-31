<?php 
use \Workerman\Worker;
use \Workerman\WebServer;
use \Workerman\Connection\TcpConnection;
use \Workerman\Connection\AsyncTcpConnection;

// 自动加载类
require_once __DIR__ . '/vendor/autoload.php';

define('STAGE_INIT', 0);
define('STAGE_ADDR', 1);
define('STAGE_UDP_ASSOC', 2);
define('STAGE_DNS', 3);
define('STAGE_CONNECTING', 4);
define('STAGE_STREAM', 5);
define('STAGE_DESTROYED', -1);


define('CMD_CONNECT', 1);
define('CMD_BIND', 2);
define('CMD_UDP_ASSOCIATE', 3);

define('ADDRTYPE_IPV4', 1);
define('ADDRTYPE_IPV6', 4);
define('ADDRTYPE_HOST', 3);


$worker = new Worker('tcp://0.0.0.0:1080');
$worker->onConnect = function($connection)
{
    $connection->stage = STAGE_INIT;
};
$worker->onMessage = function($connection, $buffer)
{
    switch($connection->stage)
    {
        case STAGE_INIT:
            $connection->send("\x05\x00");
            $connection->stage = STAGE_ADDR;
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

<?php 
use \Workerman\Worker;
use \Workerman\WebServer;
use \Workerman\Connection\TcpConnection;

// 自动加载类
require_once __DIR__ . '/../../Workerman/Autoloader.php';



// 如果不是在根目录启动，则运行runAll方法
if(!defined('GLOBAL_START'))
{
    Worker::runAll();
}
<?php

$config = [
    "auth" => [
        METHOD_NO_AUTH => true,
        METHOD_USER_PASS => function ($request) {
            return $request['user'] == 'user' && $request['pass'] == 'pass';
        }
    ],
    "log_level" => LOG_DEBUG,
    "tcp_port" => 1080,
    "udp_port" => 0,
    "wanIP" => '192.168.1.1',
];

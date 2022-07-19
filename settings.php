<?php

$app->add(new \Tuupola\Middleware\JwtAuthentication([
    "path"=>["/api/admin"],
    "secret"=>getenv('JWT_KEY'),
    "algorithm"=>['HS512'],
    "error"=>function($response,$arguments){
        $data["status"] = "error";
        $data["message"] = $arguments["message"];
        return $response
            ->withHeader("Content-Type", "application/json")
            ->write(json_encode($data,JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
    }
]));
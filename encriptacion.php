<?php
const METHOD ="AES-256-CBC";
const SECRET_KEY = '$BP@2017';
const SECRET_IV = '101712';
class Encriptacion{   

    public static function encryption($data){
        $output=false;
        $key=hash('sha256', SECRET_KEY);
        $iv = substr(hash('sha256', SECRET_IV),0,16);
        $output=openssl_encrypt($data, METHOD,$key,0,$iv);
        $output=base64_encode($output);
        return $output;
    }

    public static function decryption($data){
        $key=hash('sha256',SECRET_KEY);
        $iv = substr(hash('sha256', SECRET_IV),0,16);
        $output=openssl_decrypt(base64_decode($data),METHOD,$key,0,$iv);
        return $output;
    }
}
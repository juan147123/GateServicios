<?php
require __DIR__ . '/vendor/autoload.php';
class conexion
{
    static public function jwt($id, $email,$rol,$iat,$exp,$companyID)
    {           
        if($companyID!=''){
            $token=array(
                "iat"=>$iat,
                "exp"=>$exp,
                "data"=>[
                    "id"=>$id,                
                    "email"=>$email,
                    "rol"=>$rol,
                    "companyID"=>$companyID
                ] 
            );
        }else{
            $token=array(
                "iat"=>$iat,
                "exp"=>$exp,
                "data"=>[
                    "id"=>$id,                
                    "email"=>$email,
                    "rol"=>$rol
                ] 
            );
        }
        
        return $token;
    }
}
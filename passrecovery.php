<?php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

require __DIR__ . '/vendor/autoload.php';
class correo
{
    static public function enviarEmail($email)
    {
        $email_user = "diegomiguelnunezore@gmail.com";
        $email_password = "xurxmvpyqogvinxa";
        $the_subject = "Cambio de contraseña";
        $address_to = $email;
        $from_name = "GATE TECH SAC";
        $phpmailer = new PHPMailer();
        $body = '
            <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta http-equiv="X-UA-Compatible" content="IE=edge">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.1/dist/css/bootstrap.min.css">
                    <script src="https://cdn.jsdelivr.net/npm/jquery@3.5.1/dist/jquery.slim.min.js"></script>
                    <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js"></script>
                    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.1/dist/js/bootstrap.bundle.min.js"></script>
                    <title>Restablece tu contraseña</title>
                </head>
                <body>

                <div>
                    <div>
                    <h1>Hemos recibido una petición para restablecer la contraseña de tu cuenta.</h1>
                    <p>Si hiciste esta petición, haz clic en el siguiente botón, si no hiciste esta petición puedes ignorar este correo.</p>
                    <form action="http://gatetechsac.gsystemperu.com/changepass" method="post">
                        <strong>Enlace para restablecer tu contraseña</strong><br>
                        <input type="hidden"id="emaildesdecorreo" name="emaildesdecorreo" value="' . $email . '">
                        <button type="submit" style="width: 160px;
                        background-color: #0e12eb;
                        border: none;
                        outline: none;
                        height: 40px;
                        border-radius: 42px;
                        color: #fff;
                        text-transform: uppercase;
                        font-weight: 600;
                        margin: 10px 0;
                        cursor: pointer;
                        transition: 0.5s;
                        display: flex;
                        justify-content: center;
                        align-items: center;">Restablecer contraseña</button>
                    </form>
                    </div>
                </div>
               </body>
            </html>';
        // ---------- datos de la cuenta de Gmail -------------------------------

        //-----------------------------------------------------------------------
        // $phpmailer->SMTPDebug = 1;
        //Server settings

        $phpmailer->SMTPDebug = 0;                    
        $phpmailer->CharSet = 'UTF-8';
        $phpmailer->isSMTP();                                           
        $phpmailer->Host       = 'smtp.gmail.com; smtp-mail.outlook.com;';                     
        $phpmailer->SMTPAuth   = true;                                   

        $phpmailer->Username = $email_user;
        $phpmailer->Password = $email_password;                        
        $phpmailer->SMTPSecure = 'tls';
        $phpmailer->Port       = 587;                                 

        $phpmailer->Subject = $the_subject;
        $phpmailer->Body = $body;
        $phpmailer->AddAddress($address_to); // recipients email
        $phpmailer->setFrom($phpmailer->Username, $from_name);
        $phpmailer->IsHTML(true);
        $phpmailer->Send();
    }
}


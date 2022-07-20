<?php

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Routing\RouteCollectorProxy;
use Firebase\JWT\JWT;
use Carbon\Carbon;
use Slim\Factory\AppFactory;
use Slim\Psr7\Stream;

require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/src/container/cnf.php';
/* require __DIR__ . '/vendor/firebase/php-jwt/src/JWT.php'; */
require __DIR__ . '/auth.php';
require __DIR__ . '/passrecovery.php';
require __DIR__ . '/encriptacion.php';

$env = \Dotenv\Dotenv::create(__DIR__);
$env->load();
//$setting = require __DIR__. '/settings.php';
AppFactory::setContainer($container);

$app = AppFactory::create();
//$app = new Slim\App($setting);


$app->addErrorMiddleware(
    getenv('DISPLAY_ERROR_DETAILS'),
    getenv('DISPLAY_ERROR_DETAILS'),
    getenv('DISPLAY_ERROR_DETAILS')
);

$app->options('/{routes:.+}', function ($request, $response, $args) {
    return $response;
});

$app->add(function ($request, $handler) {
    $response = $handler->handle($request);
    return $response
        ->withHeader('Access-Control-Allow-Origin', '*')
        ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization')
        ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
});

$app->get('/', function ($request, $response, $args) {
    $response->getBody()->write('Apí Gate');
    return $response;
});
/*SECCION LOGIN */
$app->post('/login', function ($request, $response, array $args) {

    $key =  $_ENV['JWT_KEY'];
    $exp = $_ENV['JWT_HOURS_EXO'];
    $expire = Carbon::now()->addHours($exp);
    $iat =  Carbon::now()->timestamp;
    $expire = $expire->timestamp;
    $daatos = $request->getParsedBody();
    $valor1 = $daatos['email'];
    $valor2 = $daatos['password'];
    $data = $this->get('db')->select(
        'user(u)',
        '*',
        ["AND" => [
            "u.email" => $valor1,
        ]]
    );

    if (isset($data[0]['rol'])) {
        if ($data[0]['rol'] == 'Empresa') {
            $daatos = $request->getParsedBody();
            $dataUserCompany = $this->get('db')->select(
                'user(u)',
                [
                    '[><]company(c)' => ['u.ndocument' => 'ruc']
                ],
                [
                    "u.id",
                    "u.Name",
                    "u.email",
                    "u.password",
                    "u.rol",
                    "u.ndocument",
                    "u.estado",
                    "u.imagePath(imagePathUser)",
                    "company" => [
                        "c.id(companyId)",
                        "c.name",
                        "c.description",
                        "c.ruc",
                        "c.headquarter",
                        "c.imagePath"
                    ],
                ],
                ["AND" => [
                    "u.email" => $valor1
                ]]
            );

            if ($dataUserCompany) {
                $encryp = Encriptacion::encryption($valor2);
                $newData = [];
                foreach ($dataUserCompany as $row) {
                    if ($encryp == $row['password']) {
                        $newData = $row;
                        break;
                    }
                }

                if (count($newData) == 0) {
                    $dataUserCompany = array("Error" => "error");
                } else if ($newData['estado'] != "Activo") {
                    $dataUserCompany = array("Inactivo" => "inactivo");
                } else {
                    $token = conexion::jwt($dataUserCompany[0]['id'], $dataUserCompany[0]['email'], $dataUserCompany[0]['rol'], $iat, $expire, $dataUserCompany[0]['company']['companyId']);
                    $jwt = JWT::encode($token, $key, 'HS512');
                    $dataUserCompany = array('token' => $jwt, 'rol' => $dataUserCompany[0]['rol'], 'id' => $dataUserCompany[0]['id'], 'companyid' => $dataUserCompany[0]['company']['companyId']);
                }
            } else {
                $dataUserCompany = array("Error" => "error");
            }

            $response->getBody()->write(json_encode($dataUserCompany));
            return $response
                ->withHeader('Content-Type', 'application/json');
        } else {
            if ($data) {
                $encryp = Encriptacion::encryption($valor2);
                $newData = [];
                foreach ($data as $row) {
                    if ($encryp == $row['password']) {
                        $newData = $row;
                        break;
                    }
                }

                if (count($newData) == 0) {
                    $data = array("Error" => "error");
                } else if ($newData['estado'] != "Activo") {
                    $data = array("Inactivo" => "inactivo");
                } else {
                    $token = conexion::jwt($data[0]['id'], $data[0]['email'], $data[0]['rol'], $iat, $expire, '');
                    $jwt = JWT::encode($token, $key, 'HS512');
                    $data = array('token' => $jwt, 'rol' => $data[0]['rol'], 'id' => $data[0]['id']);
                }
            } else {
                $data = array("Error" => "error");
            }

            $response->getBody()->write(json_encode($data));
            return $response
                ->withHeader('Content-Type', 'application/json');
        }
    }
});

$app->post('/loginempresa', function ($request, $response, array $args) {

    $key =  $_ENV['JWT_KEY'];
    $exp = $_ENV['JWT_HOURS_EXO'];
    $expire = Carbon::now()->addHours($exp);
    $iat =  Carbon::now()->timestamp;
    $expire = $expire->timestamp;
    //$key = 'privatekey';

    $daatos = $request->getParsedBody();
    $valor1 = $daatos['email'];
    $valor2 = $daatos['password'];
    $data = $this->get('db')->select(
        'user(u)',
        '*',
        [
            "AND" => [
                "u.email" => $valor1,
                'u.isDeleted[!]' => 1,
                'u.rol' => 'Empresa'
            ]
        ]
    );

    if ($data) {
        $encryp = Encriptacion::encryption($valor2);
        $newData = [];
        foreach ($data as $row) {
            if ($encryp == $row['password']) {
                $newData = $row;
                break;
            }
        }

        if (count($newData) == 0) {
            $data = array("Error" => "error");
        } else if ($newData['estado'] != "Activo") {
            $data = array("Inactivo" => "inactivo");
        } else {
            $token = conexion::jwt($data[0]['id'], $data[0]['email'], $data[0]['rol'], $iat, $expire, '');
            $jwt = JWT::encode($token, $key, 'HS512');
            $data = array('token' => $jwt, 'rol' => $data[0]['rol'], 'id' => $data[0]['id']);
        }
    } else {
        $data = array("Error" => "error");
    }
    $response->getBody()->write(json_encode($data));
    return $response
        ->withHeader('Content-Type', 'application/json');
});

/*SECCION RECUPERAR CONTRASEÑA*/
$app->post('/passrecovery', function ($request, $response, array $args) {

    $daatos = $request->getParsedBody();
    $valor1 = $daatos['email'];
    $data = $this->get('db')->select(
        'user(u)',
        '*',
        ["AND" => [
            "u.email" => "$valor1",
            'u.isDeleted[!]' => 1
        ]]
    );

    if ($data) {
        correo::enviarEmail($valor1);
        $data = array('Respuesta' => "Usuario Encontrado");
    } else {
        $data = array("Error" => "error");
    }
    $response->getBody()->write(json_encode($data));
    return $response
        ->withHeader('Content-Type', 'application/json');
});

$app->put('/passupdate', function ($request, $response, array $args) {

    $daatos = $request->getParsedBody();
    $valor1 = $daatos['email'];
    $valor2 = $daatos['password'];
    $encryp = Encriptacion::encryption($valor2);
    $valor3 = $daatos['newpassword'];
    if ($valor2 != $valor3) {
        $data = array('Respuesta' => "Contrasenas diferentes");
    } else {
        $data = $this->get('db')->update(
            'user',
            [
                "password" => $encryp,
            ],
            ['email' => $valor1]
        );
        if ($data) {
            $data = array('Respuesta' => "Contrasena Actualizada");
        } else {
            $data = array("Error" => "error");
        }
    }

    $response->getBody()->write(json_encode($data));
    return $response
        ->withHeader('Content-Type', 'application/json');
});

$app->addBodyParsingMiddleware();
$app->group('/api/', function (RouteCollectorProxy $group) {
    /**eequipo */
    $group->get('equipoporempresa/{idempresa}', function ($request, $response, array $args) {
        $id = $args['idempresa'];
        $data = $this->get('db')->select(
            'equipment(e)',
            [
                '[><]equipment_type(et)' => ['equipmentTypeId' => 'id'],
                '[><]company(c)' => ['e.companyId' => 'id']
            ],
            [
                "e.id",
                "e.description",
                "e.code",
                "e.isDeleted",
                "e.estado",
                "companyId" => [
                    "c.id(idcompany)",
                    "c.name",
                    "c.description(companydescription)",
                    "c.isDeleted(companyisDeleted)",
                    "c.ruc",
                    "c.headquarter",
                ],
                "equipmentTypeId" => [
                    "et.id(idequipmentType)",
                    "et.name(nameequipmentType)",
                    "et.isDeleted(isDeletedequipmentType)"
                ]

            ],
            [
                "AND" => [
                    'c.id' => $id,
                ],
                "ORDER" => ["e.id" => "DESC"]
            ]
        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    /*enpot para la app */
    $group->get('equipment/{idempresa}', function ($request, $response, array $args) {
        $id = $args['idempresa'];
        $data = $this->get('db')->select(
            'equipment(e)',
            [
                '[><]equipment_type(et)' => ['equipmentTypeId' => 'id'],
                '[><]company(c)' => ['e.companyId' => 'id']
            ],
            [
                "e.id",
                "e.description",
                "e.code",
                "e.isDeleted",
                "e.estado",
                "companyId" => [
                    "c.id(idcompany)",
                    "c.name",
                    "c.description(companydescription)",
                    "c.isDeleted(companyisDeleted)",
                    "c.ruc",
                    "c.headquarter",
                ],
                "equipmentTypeId" => [
                    "et.id(idequipmentType)",
                    "et.name(nameequipmentType)",
                    "et.isDeleted(isDeletedequipmentType)"
                ]

            ],
            [
                "AND" => [
                    'e.id' => $id,
                ],
                "ORDER" => ["e.id" => "DESC"]
            ]
        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->get('equipoporempresa/select/{idempresa}', function ($request, $response, array $args) {
        $id = $args['idempresa'];
        $data = $this->get('db')->select(
            'equipment(e)',
            [
                '[><]equipment_type(et)' => ['equipmentTypeId' => 'id'],
                '[><]company(c)' => ['e.companyId' => 'id']
            ],
            [
                "e.id",
                "e.description",
                "e.code",
                "e.isDeleted",
                "e.estado",
                "companyId" => [
                    "c.id(idcompany)",
                    "c.name",
                    "c.description(companydescription)",
                    "c.isDeleted(companyisDeleted)",
                    "c.ruc",
                    "c.headquarter",
                ],
                "equipmentTypeId" => [
                    "et.id(idequipmentType)",
                    "et.name(nameequipmentType)",
                    "et.isDeleted(isDeletedequipmentType)"
                ]

            ],
            [
                "AND" => [
                    'e.companyId' => $id,
                    'e.isDeleted[!]' => 1,
                ],
                "ORDER" => ["e.id" => "DESC"]
            ]
        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->get('equipo/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->select(
            'equipment(e)',
            [
                '[><]equipment_type(et)' => ['equipmentTypeId' => 'id'],
                '[><]company(c)' => ['e.companyId' => 'id']
            ],
            [
                "e.id",
                "e.description",
                "e.code",
                "e.isDeleted",
                "e.estado",
                "companyId" => [
                    "c.id(idcompany)",
                    "c.name",
                    "c.description(companydescription)",
                    "c.isDeleted(companyisDeleted)",
                    "c.ruc",
                    "c.headquarter",
                ],
                "equipmentTypeId" => [
                    "et.id(idequipmentType)",
                    "et.name(nameequipmentType)",
                    "et.isDeleted(isDeletedequipmentType)"
                ]
            ],
            ['e.id' => $id]
        );

        if (!$data) {
            $data = array("Respuesta" => "No se encontro");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->post('equipo', function ($request, $response, array $args) {
        //$id = $args['id'];
        $daatos = $request->getParsedBody();
        $valor1 = $daatos['description'];
        $valor2 = $daatos['code'];
        $valor4 = $daatos['companyId'];
        $valor5 = $daatos['equipmentTypeId'];
        $data = $this->get('db')->insert('equipment', [
            "description" => $valor1,
            "code" => $valor2,
            "companyId" => $valor4,
            "equipmentTypeId" => $valor5,
        ]);
        if ($data) {
            $data = array("Respuesta" => "Registro Exitoso");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->put('equipo', function ($request, $response, array $args) {
        //$id = $args['id'];
        $daatos = $request->getParsedBody();
        $valor1 = $daatos['description'];
        $valor2 = $daatos['code'];
        $valor4 = $daatos['companyId'];
        $valor5 = $daatos['equipmentTypeId'];
        $valor6 = $daatos['estado'];
        $id = $daatos['id'];
        if ($valor6 == "Activo") {
            $isdelete = 0;
        } else {
            $isdelete = 1;
        }
        $data = $this->get('db')->update('equipment', [
            "description" => $valor1,
            "code" => $valor2,
            "companyId" => $valor4,
            "isDeleted" => $isdelete,
            "estado" => $valor6,
            "equipmentTypeId" => $valor5,
        ], ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "Se actualizó Correctamente");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->delete('equipo/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->delete('equipment', ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "dato eliminado");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->put('equipo/cambioestado', function ($request, $response, array $args) {
        //$id = $args['id'];
        $daatos = $request->getParsedBody();
        $id = $daatos['id'];
        $isDeleted = $daatos['isDeleted'];
        $data = $this->get('db')->update('equipment', [
            "isDeleted" => $isDeleted,
            "estado" => 'Inactivo'
        ], ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "Se elimino Correctamente");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    /**Tipo de equipo */
    $group->get('equipo/tipo/', function ($request, $response, array $args) {
        $data = $this->get('db')->select('equipment_type', '*', [
            //'isDeleted[!]' => 1,
            "ORDER" => ["id" => "DESC"]
        ]);
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->get('equipo/tipo/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->select('equipment_type', '*', ['id' => $id]);
        if (!$data) {
            $data = array("Respuesta" => "No se encontro");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->get('equipo/tipo/listarcombo/', function ($request, $response, array $args) {
        $data = $this->get('db')->select('equipment_type', '*', ['isDeleted[!]' => 1]);
        if (!$data) {
            $data = array("Respuesta" => "No se encontro");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->post('equipo/tipo/', function ($request, $response, array $args) {
        $daatos = $request->getParsedBody();
        $name = $daatos['name'];
        $data = $this->get('db')->insert('equipment_type', [

            "name" => $name
        ]);
        if ($data) {
            $data = array("Respuesta" => "Registro Exitoso");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->put('equipo/tipo/', function ($request, $response, array $args) {
        $daatos = $request->getParsedBody();
        $name = $daatos['name'];
        $estado = $daatos['estado'];
        $id = $daatos['id'];
        if ($estado == "Activo") {
            $isdelete = 0;
        } else {
            $isdelete = 1;
        }
        $data = $this->get('db')->update('equipment_type', [
            "name" => $name,
            "isDeleted" => $isdelete,
            "estado" => $estado
        ], ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "Se actualizó Correctamente");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->delete('equipo/tipo/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->delete('equipment_type', ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "dato eliminado");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->put('equipo/tipo/cambioestado', function ($request, $response, array $args) {
        //$id = $args['id'];
        $daatos = $request->getParsedBody();
        $isDeleted = $daatos['isDeleted'];
        $id = $daatos['id'];
        $data = $this->get('db')->update('equipment_type', [
            "isDeleted" => $isDeleted,
            "estado" => 'Inactivo'
        ], ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "Se elimino Correctamente");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    /**empresa */
    $group->get('empresa', function ($request, $response, array $args) {
        $data = $this->get('db')->select('company', '*', [
            'isDeleted[!]' => 1,
            "ORDER" => ["id" => "DESC"]
        ]);
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->get('empresa/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->select(
            'company(c)',
            [
                '[>]user(u)' => ['c.ruc' => 'ndocument'],
            ],
            [
                "c.id",
                "c.name",
                "c.description",
                "c.isDeleted",
                "c.ruc",
                "c.headquarter",
                "c.estado",
                "CompanyUser" => [
                    "u.id(idU)",
                    "u.Name(NameU)",
                    "u.email(emailU)",
                    "u.isDeleted(UisDeleted)",
                    "u.rol(rolTu)",
                    "u.documentTypeId(documentU)",
                    "u.ndocument (ndocumentU)",
                    "u.password (passU)",
                ]
            ],
            [
                "AND" => [
                    'c.id' => $id,
                ]
            ]
        );
        if (!$data) {
            $data = array("Respuesta" => "No se encontro");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    $group->get('empresaruc/{ruc}', function ($request, $response, array $args) {
        $ruc = $args['ruc'];
        $data = $this->get('db')->select(
            'company(c)',
            [
                '[>]user(u)' => ['c.ruc' => 'ndocument'],
            ],
            [
                "c.id",
                "c.name",
                "c.description",
                "c.isDeleted",
                "c.ruc",
                "c.headquarter",
                "c.estado",

            ],
            [
                "AND" => [
                    'c.ruc' => $ruc,
                ]
            ]
        );
        if (!$data) {
            $data = array("Respuesta" => "No se encontro");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    $group->post('nombreempresa', function ($request, $response, array $args) {
        $daatos = $request->getParsedBody();
        $name = $daatos['name'];
        $data = $this->get('db')->select('company', '*', [
            "AND" => [
                'name[~]' => "$name"
            ],
            "ORDER" => ["id" => "DESC"]
        ]);
        if (!$data) {
            $data = array("Respuesta" => "No se encontro");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->post('empresa', function ($request, $response, array $args) {

        $daatos = $request->getParsedBody();
        $name = $daatos['name'];
        $description = $daatos['description'];
        $ruc = $daatos['ruc'];
        $headquarter = $daatos['headquarter'];
        $image_name = $daatos['nameImage'];
        $imagePath = $daatos['imagePath'];
        if ($imagePath) {
            $image_upload_dir = $_SERVER['DOCUMENT_ROOT'] . '/imagePath/' . $image_name;
            $protocol = stripos($_SERVER['SERVER_PROTOCOL'], 'https') === true ? 'https://' : 'http://';
            $imagenUrl = $protocol . $_SERVER['SERVER_NAME'] . '/imagePath/' . $image_name;
        } else {
            $imagenUrl = "";
        }

        $data = $this->get('db')->insert('company', [
            "name" => $name,
            "description" => $description,
            "ruc" => $ruc,
            "headquarter" => $headquarter,
            "imagePath" => $imagenUrl,
        ]);

        if ($data) {
            $data = array("Respuesta" => "Registro Exitoso");
            if ($image_name != '') {
                file_put_contents($image_upload_dir, base64_decode($imagePath));
            }
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->put('empresa', function ($request, $response, array $args) {
        $daatos = $request->getParsedBody();
        $name = $daatos['name'];
        $description = $daatos['description'];
        $ruc = $daatos['ruc'];
        $headquarter = $daatos['headquarter'];
        $rucHidden = $daatos['rucHidden'];
        $id = $daatos['id'];

        $data = $this->get('db')->update('company', [
            "name" => $name,
            "description" => $description,
            "ruc" => $ruc,
            "headquarter" => $headquarter,
        ], ['id' => $id]);

        $data = $this->get('db')->update('user', [
            "name" => $name,
            "ndocument" => $ruc,
        ], ['ndocument' => $rucHidden]);

        if ($data) {
            $data = array("Respuesta" => "Se actualizo Correctamente");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->put('empresa/updateimage', function ($request, $response, array $args) {

        $daatos = $request->getParsedBody();
        $image_name = $daatos['nameImage'];
        $imagePath = $daatos['imagePath'];
        $image_upload_dir = $_SERVER['DOCUMENT_ROOT'] . '/imagePath/' . $image_name;

        $id = $daatos['id'];
        $protocol = stripos($_SERVER['SERVER_PROTOCOL'], 'https') === true ? 'https://' : 'http://';
        $imagenUrl = $protocol . $_SERVER['SERVER_NAME'] . '/imagePath/' . $image_name;
        $data = $this->get('db')->update('company', [
            "imagePath" => $imagenUrl
        ], ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "Se actualizó Correctamente");
            file_put_contents($image_upload_dir, base64_decode($imagePath));
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->put('empresa/reingresar', function ($request, $response, array $args) {
        $daatos = $request->getParsedBody();
        $id = $daatos['id'];
        $data = $this->get('db')->update('company', [
            "isDeleted" => '0',
            "estado" => 'Activo'
        ], ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "Reingreso");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->delete('empresa/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->delete('company', ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "dato eliminado");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->put('empresa/cambioestado', function ($request, $response, array $args) {
        $daatos = $request->getParsedBody();
        $id = $daatos['id'];
        $data = $this->get('db')->update('company', [
            "isDeleted" => '1',
            "estado" => 'Inactivo'
        ], ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "Se elimino Correctamente");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });



    //TECHNICAL REVIEW LIST FOR ID company
    $group->get('technicalreview/{id}/{technicalUserId}', function ($request, $response, array $args) {
        $id = $args['id'];
        $tecid = $args['technicalUserId'];
        $data = $this->get('db')->select(
            'company(c)',
            [
                '[><]equipment(e)' => ['c.id' => 'companyId'],
                '[><]technical_review(tr)' => ['e.id' => 'equipmentId'],
                '[>]company_employees(ce)' => ['tr.supervisorUserId' => 'id'],
                '[>]company_employees(cem)' => ['tr.supervisorMinId' => 'id'],
                '[>]user(u)' => ['tr.technicalUserId' => 'id'],
            ],
            [
                "tr.id",
                "tr.title",
                "tr.content",
                "tr.conclusions",
                "tr.status",
                "tr.isDeleted",
                "tr.inspectionDate",
                "tr.estado",
                "tr.target",
                "equipmentId" => [
                    "e.id(idequipment)",
                    "e.description(equipmentdescription)",
                    "e.code",
                    "e.isDeleted(equipmentisDeleted)",
                    "e.companyId",
                    "e.equipmentTypeId",
                ],
                "technicalUserId" => [
                    "u.id(idusertu)",
                    "u.Name(NameTu)",
                    "u.email(emailTu)",
                    "u.isDeleted(techisDeleted)",
                    "u.rol(rolTu)",
                    "u.documentTypeId(documentTu)",
                    "u.ndocument (ndocumentTu)",
                    "u.imagePath"
                ],
                "supervisorUserId" => [
                    "ce.id(iduserSu)",
                    "ce.name(NameSu)",
                    "ce.documentTypeId(sudoctype)",
                    "ce.document(sudoc)",
                    "ce.email(emailSu)",
                    "ce.phone",
                    "ce.rol(rolSu)",
                    "ce.isDeleted(superisDeleted)"
                ],
                "supervisorMinId" => [
                    "cem.id(iduserSuM)",
                    "cem.name(NameSuM)",
                    "cem.documentTypeId(sudoctypeM)",
                    "cem.document(sudocM)",
                    "cem.email(emailSuM)",
                    "cem.phone(phonesuM)",
                    "cem.rol(rolSuM)",
                    "cem.isDeleted(superisDeletedM)"
                ]
            ],
            [
                "AND" => [
                    'c.id' => $id,
                    'tr.technicalUserId ' => $tecid,
                ],
                "ORDER" => ["tr.id" => "DESC"],
            ]
        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    /* TECHNICAL REVIEW LIST FOR ID */
    $group->get('technicalreviewid/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->select(
            'company(c)',
            [
                '[><]equipment(e)' => ['c.id' => 'companyId'],
                '[><]technical_review(tr)' => ['e.id' => 'equipmentId'],
                '[>]company_employees(cem)' => ['tr.supervisorMinId' => 'id'],
                '[>]user(u)' => ['tr.technicalUserId' => 'id'],
                '[>]company_employees(ce)' => ['tr.supervisorUserId' => 'id'],
            ],
            [
                "tr.id",
                "tr.title",
                "tr.content",
                "tr.conclusions",
                "tr.status",
                "tr.isDeleted",
                "tr.inspectionDate",
                "tr.estado",
                "tr.target",
                "equipmentId" => [
                    "e.id(idequipment)",
                    "e.description(equipmentdescription)",
                    "e.code",
                    "e.isDeleted(equipmentisDeleted)",
                    "e.companyId",
                    "e.equipmentTypeId",
                ],
                "technicalUserId" => [
                    "u.id(idusertu)",
                    "u.Name(NameTu)",
                    "u.email(emailTu)",
                    "u.isDeleted(techisDeleted)",
                    "u.rol(rolTu)",
                    "u.documentTypeId(documentTu)",
                    "u.ndocument (ndocumentTu)",
                    "u.imagePath"
                ],
                "supervisorUserId" => [
                    "ce.id(iduserSu)",
                    "ce.name(NameSu)",
                    "ce.documentTypeId(sudoctype)",
                    "ce.document(sudoc)",
                    "ce.email(emailSu)",
                    "ce.phone",
                    "ce.rol(rolSu)",
                    "ce.isDeleted(superisDeleted)"
                ],
                "supervisorMinId" => [
                    "cem.id(iduserSuM)",
                    "cem.name(NameSuM)",
                    "cem.documentTypeId(sudoctypeM)",
                    "cem.document(sudocM)",
                    "cem.email(emailSuM)",
                    "cem.phone(phonesuM)",
                    "cem.rol(rolSuM)",
                    "cem.isDeleted(superisDeletedM)"
                ],

            ],
            [
                "AND" => [
                    'tr.id' => $id
                ],
                "ORDER" => ["tr.id" => "DESC"],
            ]
        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    //TECHNICAL REVIEW LIST FOR ID USER AND STATUS
    $group->get('technicalreview/user/{id}/{status}', function ($request, $response, array $args) {
        $id = $args['id'];
        $status = $args['status'];
        $data = $this->get('db')->select(
            'company(c)',
            [
                '[><]equipment(e)' => ['c.id' => 'companyId'],
                '[><]technical_review(tr)' => ['e.id' => 'equipmentId'],
                '[>]company_employees(ce)' => ['tr.supervisorUserId' => 'id'],
                '[>]user(u)' => ['tr.technicalUserId' => 'id'],
            ],
            [
                "tr.id",
                "tr.title",
                "tr.content",
                "tr.conclusions",
                "tr.status",
                "tr.isDeleted",
                "tr.inspectionDate",
                "equipmentId" => [
                    "e.id(idequipment)",
                    "e.description(equipmentdescription)",
                    "e.code",
                    "e.isDeleted(equipmentisDeleted)",
                    "e.companyId",
                    "e.equipmentTypeId",
                ],
                "technicalUserId" => [
                    "u.id(idusertu)",
                    "u.Name(NameTu)",
                    "u.email(emailTu)",
                    "u.isDeleted(techisDeleted)",
                    "u.rol(rolTu)",
                    "u.documentTypeId(documentTu)",
                    "u.ndocument (ndocumentTu)",
                    "u.imagePath"
                ],
                "supervisorUserId" => [
                    "ce.id(iduserSu)",
                    "ce.name(NameSu)",
                    "ce.documentTypeId(sudoctype)",
                    "ce.document(sudoc)",
                    "ce.email(emailSu)",
                    "ce.phone",
                    "ce.rol(rolSu)",
                    "ce.isDeleted(superisDeleted)"
                ],
                "companyId" => [
                    "c.id(idcompany)",
                    "c.name"
                ]
            ],
            [
                "AND" => [
                    'u.id' => $id,
                    'tr.status' => $status,
                    'c.isDeleted[!]' => 1,
                    'tr.isDeleted[!]' => 1,
                ],
                "ORDER" => ["tr.id" => "DESC"],
            ]
        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    //TECHNICAL REVIEW LIST pendiente
    $group->get('technicalreview/allreviewpendiente', function ($request, $response, array $args) {

        $data = $this->get('db')->select(
            'company(c)',
            [
                '[><]equipment(e)' => ['c.id' => 'companyId'],
                '[><]technical_review(tr)' => ['e.id' => 'equipmentId'],
                '[>]company_employees(ce)' => ['tr.supervisorUserId' => 'id'],
                '[>]user(u)' => ['tr.technicalUserId' => 'id'],
            ],
            [
                "tr.id",
                "tr.title",
                "tr.content",
                "tr.conclusions",
                "tr.status",
                "tr.isDeleted",
                "tr.inspectionDate",
                "equipmentId" => [
                    "e.id(idequipment)",
                    "e.description(equipmentdescription)",
                    "e.code",
                    "e.isDeleted(equipmentisDeleted)",
                    "e.companyId",
                    "e.equipmentTypeId",
                ],
                "technicalUserId" => [
                    "u.id(idusertu)",
                    "u.Name(NameTu)",
                    "u.email(emailTu)",
                    "u.isDeleted(techisDeleted)",
                    "u.rol(rolTu)",
                    "u.documentTypeId(documentTu)",
                    "u.ndocument (ndocumentTu)",
                    "u.imagePath"
                ],
                "supervisorUserId" => [
                    "ce.id(iduserSu)",
                    "ce.name(NameSu)",
                    "ce.documentTypeId(sudoctype)",
                    "ce.document(sudoc)",
                    "ce.email(emailSu)",
                    "ce.phone",
                    "ce.rol(rolSu)",
                    "ce.isDeleted(superisDeleted)"
                ],
                "companyId" => [
                    "c.id(idcompany)",
                    "c.name"
                ]
            ],
            [
                "AND" => [
                    'tr.status' => 'PENDIENTE',
                    'c.isDeleted[!]' => 1,
                    'tr.isDeleted[!]' => 1,
                ],
                "ORDER" => ["tr.id" => "DESC"],
            ]
        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    //TECHNICAL REVIEW LIST progreso
    $group->get('technicalreview/allreviewprogreso', function ($request, $response, array $args) {

        $data = $this->get('db')->select(
            'company(c)',
            [
                '[><]equipment(e)' => ['c.id' => 'companyId'],
                '[><]technical_review(tr)' => ['e.id' => 'equipmentId'],
                '[>]company_employees(ce)' => ['tr.supervisorUserId' => 'id'],
                '[>]user(u)' => ['tr.technicalUserId' => 'id'],
            ],
            [
                "tr.id",
                "tr.title",
                "tr.content",
                "tr.conclusions",
                "tr.status",
                "tr.isDeleted",
                "tr.inspectionDate",
                "equipmentId" => [
                    "e.id(idequipment)",
                    "e.description(equipmentdescription)",
                    "e.code",
                    "e.isDeleted(equipmentisDeleted)",
                    "e.companyId",
                    "e.equipmentTypeId",
                ],
                "technicalUserId" => [
                    "u.id(idusertu)",
                    "u.Name(NameTu)",
                    "u.email(emailTu)",
                    "u.isDeleted(techisDeleted)",
                    "u.rol(rolTu)",
                    "u.documentTypeId(documentTu)",
                    "u.ndocument (ndocumentTu)",
                    "u.imagePath"
                ],
                "supervisorUserId" => [
                    "ce.id(iduserSu)",
                    "ce.name(NameSu)",
                    "ce.documentTypeId(sudoctype)",
                    "ce.document(sudoc)",
                    "ce.email(emailSu)",
                    "ce.phone",
                    "ce.rol(rolSu)",
                    "ce.isDeleted(superisDeleted)"
                ],
                "companyId" => [
                    "c.id(idcompany)",
                    "c.name"
                ]
            ],
            [
                "AND" => [
                    'tr.status' => 'EN PROGRESO',
                    'c.isDeleted[!]' => 1,
                    'tr.isDeleted[!]' => 1,
                ],
                "ORDER" => ["tr.id" => "DESC"],
            ]
        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    //TECHNICAL REVIEW LIST completado
    $group->get('technicalreview/allreviewcompletado', function ($request, $response, array $args) {

        $data = $this->get('db')->select(
            'company(c)',
            [
                '[><]equipment(e)' => ['c.id' => 'companyId'],
                '[><]technical_review(tr)' => ['e.id' => 'equipmentId'],
                '[>]company_employees(ce)' => ['tr.supervisorUserId' => 'id'],
                '[>]user(u)' => ['tr.technicalUserId' => 'id'],
            ],
            [
                "tr.id",
                "tr.title",
                "tr.content",
                "tr.conclusions",
                "tr.status",
                "tr.isDeleted",
                "tr.inspectionDate",
                "equipmentId" => [
                    "e.id(idequipment)",
                    "e.description(equipmentdescription)",
                    "e.code",
                    "e.isDeleted(equipmentisDeleted)",
                    "e.companyId",
                    "e.equipmentTypeId",
                ],
                "technicalUserId" => [
                    "u.id(idusertu)",
                    "u.Name(NameTu)",
                    "u.email(emailTu)",
                    "u.isDeleted(techisDeleted)",
                    "u.rol(rolTu)",
                    "u.documentTypeId(documentTu)",
                    "u.ndocument (ndocumentTu)",
                    "u.imagePath"
                ],
                "supervisorUserId" => [
                    "ce.id(iduserSu)",
                    "ce.name(NameSu)",
                    "ce.documentTypeId(sudoctype)",
                    "ce.document(sudoc)",
                    "ce.email(emailSu)",
                    "ce.phone",
                    "ce.rol(rolSu)",
                    "ce.isDeleted(superisDeleted)"
                ],
                "companyId" => [
                    "c.id(idcompany)",
                    "c.name"
                ]
            ],
            [
                "AND" => [
                    'tr.status' => 'COMPLETADO',
                    'c.isDeleted[!]' => 1,
                    'tr.isDeleted[!]' => 1,
                ],
                "ORDER" => ["tr.id" => "DESC"],
            ]
        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->get('technicalreviewaprobadas/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->select(
            'company(c)',
            [
                '[><]equipment(e)' => ['c.id' => 'companyId'],
                '[><]technical_review(tr)' => ['e.id' => 'equipmentId'],
                '[>]company_employees(ce)' => ['tr.supervisorUserId' => 'id'],
                '[>]user(u)' => ['tr.technicalUserId' => 'id'],
            ],
            [
                "tr.id",
                "tr.title",
                "tr.content",
                "tr.conclusions",
                "tr.status",
                "tr.isDeleted",
                "tr.inspectionDate",
                "equipmentId" => [
                    "e.id(idequipment)",
                    "e.description(equipmentdescription)",
                    "e.code",
                    "e.isDeleted(equipmentisDeleted)",
                    "e.companyId",
                    "e.equipmentTypeId",
                ],
                "technicalUserId" => [
                    "u.id(idusertu)",
                    "u.Name(NameTu)",
                    "u.email(emailTu)",
                    "u.isDeleted(techisDeleted)",
                    "u.rol(rolTu)",
                    "u.documentTypeId(documentTu)",
                    "u.ndocument (ndocumentTu)",
                    "u.imagePath"
                ],
                "supervisorUserId" => [
                    "ce.id(iduserSu)",
                    "ce.name(NameSu)",
                    "ce.documentTypeId(sudoctype)",
                    "ce.document(sudoc)",
                    "ce.email(emailSu)",
                    "ce.phone",
                    "ce.rol(rolSu)",
                    "ce.isDeleted(superisDeleted)"
                ]
            ],
            [
                "AND" => [
                    ['c.id' => $id],
                    'tr.status' => 'Aprobada'
                ],
                "ORDER" => ["tr.id" => "DESC"]
            ]
        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    //TECHNICAL REVIEW REGISTRY
    $group->post('technicalreview', function ($request, $response, array $args) {

        $datos = $request->getParsedBody();
        $titleTR = $datos['title'];
        $inspectionDateTR = $datos['inspectionDate'];
        $equipmentIdTR = $datos['equipmentId'];
        $technicalUserIdTR = $datos['technicalUserId'];
        $supervisorUserIdTR = $datos['supervisorUserId'];
        $supervisorMinId = $datos['supervisorMinId'];
        $target = $datos['target'];
        if ($supervisorUserIdTR == null || $supervisorUserIdTR == "") {
            $supervisorUserIdTR = null;
        }
        if ($supervisorMinId == null || $supervisorMinId == "") {
            $supervisorMinId = null;
        }
        $data = $this->get('db')->insert('technical_review', [
            "title" => $titleTR,
            "inspectionDate" => $inspectionDateTR,
            "equipmentId" => $equipmentIdTR,
            "technicalUserId" => $technicalUserIdTR,
            "supervisorUserId" => $supervisorUserIdTR,
            "supervisorMinId" => $supervisorMinId,
            "target" => $target
        ]);
        if ($data) {
            $data = array("Respuesta" => "Registro Exitoso");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    //TECHNICAL REVIEW UPDATE
    $group->put('technicalreview', function ($request, $response, array $args) {
        $datos = $request->getParsedBody();

        $idTR = $datos['id'];
        $titleTR = $datos['title'];
        $inspectionDateTR = $datos['inspectionDate'];
        $equipmentIdTR = $datos['equipmentId'];
        $supervisorUserIdTR = $datos['supervisorUserId'];
        $supervisorMinIdTR = $datos['supervisorMinId'];
        $target = $datos['target'];
        $estado = $datos['estado'];
        if ($estado == "Activo") {
            $isdelete = 0;
        } else {
            $isdelete = 1;
        }

        if ($supervisorUserIdTR == null || $supervisorUserIdTR == "") {
            $supervisorUserIdTR = null;
        }
        if ($supervisorMinIdTR == null || $supervisorMinIdTR == "") {
            $supervisorMinIdTR = null;
        }
        $data = $this->get('db')->update('technical_review', [
            "title" => $titleTR,
            "inspectionDate" => $inspectionDateTR,
            "equipmentId" => $equipmentIdTR,
            "supervisorUserId" => $supervisorUserIdTR,
            "supervisorMinId" => $supervisorMinIdTR,
            "isDeleted" => $isdelete,
            "target" => $target,
            "estado" => $estado
        ], ['id' => $idTR]);
        if ($data) {
            $data = array("Respuesta" => "Actualizacion Exitosa");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    //TECHNICAL REVIEW UPDATE PAGE
    $group->put('technicalreview/all', function ($request, $response, array $args) {
        $datos = $request->getParsedBody();

        $idTR = $datos['id'];
        $inspectionDateTR = $datos['inspectionDate'];
        $equipmentIdTR = $datos['equipmentId'];
        $supervisorUserIdTR = $datos['supervisorUserId'];
        $supervisorMinIdTR = $datos['supervisorMinId'];
        $content = $datos['content'];

        $data = $this->get('db')->update('technical_review', [
            "content" => $content,
            "inspectionDate" => $inspectionDateTR,
            "equipmentId" => $equipmentIdTR,
            "supervisorUserId" => $supervisorUserIdTR,
            "supervisorMinId" => $supervisorMinIdTR,
        ], ['id' => $idTR]);
        if ($data) {
            $data = array("Respuesta" => "Actualizacion Exitosa");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    //TECHNICAL REVIEW UPDATE CONCLUSIONS
    $group->put('technicalreview/conclusions', function ($request, $response, array $args) {
        $datos = $request->getParsedBody();

        $idTR = $datos['id'];
        $conclusions = $datos['conclusions'];

        $data = $this->get('db')->update('technical_review', [
            "conclusions" => $conclusions,
        ], ['id' => $idTR]);
        if ($data) {
            $data = array("Respuesta" => "Actualizacion Exitosa");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    //TECHNICAL REVIEW DELETE
    $group->delete('technicalreview/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->delete('technical_review', ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "dato eliminado");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });


    //TECHNICAL REVIEW LOGICAL DELETE
    $group->put('technicalreview/logicaldelete', function ($request, $response, array $args) {
        $datos = $request->getParsedBody();
        $id = $datos['id'];
        $data = $this->get('db')->update('technical_review', [
            "isDeleted" => "1",
            "estado" => "Inactivo"
        ], ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "Se elimino Correctamente");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });


    //FILE TECHNICAL LIST

    $group->get('filetechnical/image/{id}', function ($request, $response, array $args) {
        $technicalReviewId = $args['id'];
        $data = $this->get('db')->select(
            'technical_review(tr)',
            [
                '[><]file_technical(ft)' => ['tr.id' => 'technicalReviewId']
            ],
            [
                "ft.id",
                "ft.isDeleted(ftisDelete)",
                "ft.filePath(ftfilePath)",
                "ft.fecha",
                "technicalReviewId" => [
                    "tr.id(idTR)",
                    "tr.title",
                    "tr.content",
                    "tr.conclusions",
                    "tr.status",
                    "tr.isDeleted",
                    "tr.inspectionDate",
                    "tr.equipmentId",
                    "tr.technicalUserId",
                    "tr.supervisorUserId",
                ]
            ],
            [
                "AND" => [
                    'ft.technicalReviewId' => $technicalReviewId
                ]
            ]
        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });


    //FILE TECHNICAL LIST FOR ID

    $group->get('filetechnical/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->select(
            'file_technical(ft)',
            [
                '[><]technical_review(tr)' => ['ft.technicalReviewId' => 'id']
            ],
            [
                "ft.id",
                "ft.isDeleted(ftisDelete)",
                "ft.filePath(ftfilePath)",
                "technicalReviewId" => [
                    "tr.id(idTR)",
                    "tr.title",
                    "tr.content",
                    "tr.conclusions",
                    "tr.status",
                    "tr.isDeleted",
                    "tr.inspectionDate",
                    "tr.equipmentId",
                    "tr.technicalUserId",
                    "tr.supervisorUserId",
                ]
            ],
            ['ft.id' => $id]
        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    //FILE TECHNICAL REGISTRY
    $group->post('filetechnical', function ($request, $response, array $args) {
        $datos = $request->getParsedBody();
        $id = $datos['id'];
        $filePath = $datos['filePath'];
        $isDelete = $datos['isDeleted'];
        $technicalReviewId = $datos['technicalReviewId'];
        $data = $this->get('db')->insert('file_technical', [
            "id" => $id,
            "filePath" => $filePath,
            "isDeleted" => $isDelete,
            "technicalReviewId" => $technicalReviewId,
        ]);
        if ($data) {
            $data = array("Respuesta" => "Registro Exitoso");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    //FILE TECHNICAL UPDATE
    $group->put('filetechnical', function ($request, $response, array $args) {
        $datos = $request->getParsedBody();
        $id = $datos['id'];
        $filePath = $datos['filePath'];
        $isDelete = $datos['isDeleted'];
        $technicalReviewId = $datos['technicalReviewId'];
        $data = $this->get('db')->update('file_technical', [
            "filePath" => $filePath,
            "isDeleted" => $isDelete,
            "technicalReviewId" => $technicalReviewId
        ], ["id" => $id]);
        if ($data) {
            $data = array("Respuesta" => "Actualizacion Exitosa");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });


    //FILE TECHNICAL DELETE
    $group->delete('filetechnical/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->delete('file_technical', ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "dato eliminado");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });


    //FILE TECHNICAL LOGICAL DELETE
    $group->put('filetechnical/logicaldelete', function ($request, $response, array $args) {
        $datos = $request->getParsedBody();
        $isDeleted = $datos['isDeleted'];
        $id = $datos['id'];
        $data = $this->get('db')->update('file_technical', [
            "isDeleted" => $isDeleted
        ], ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "Se actualizó Correctamente");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });



    //FILL LEVEL LIST

    $group->get('fillLevel/technicalreview/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->select(
            'technical_review(tr)',
            [
                '[><]fill_level(fl)' => ['tr.id' => 'technicalReviewId'],
                '[><]equipment(eq)' => ['tr.equipmentId' => 'id'],
                '[><]company(c)' => ['eq.companyId' => 'id'],
            ],
            [
                "fl.id",
                "fl.diameter",
                "fl.totalNumberLifters",
                "fl.exposedLifter",
                "fl.height",
                "fl.fillingLevel",
                "fl.imagen",
                "fl.description",
                "fl.isDeleted(flisDelete)",
                "technicalReviewId" => [
                    "tr.id(idTR)",
                    "tr.title",
                    "tr.content",
                    "tr.conclusions",
                    "tr.status",
                    "tr.isDeleted",
                    "tr.inspectionDate",
                    "tr.equipmentId",
                    "tr.technicalUserId",
                    "tr.supervisorUserId",
                ],
                "companyId" => [
                    "c.id(idcompany)",
                    "c.name"
                ]

            ],
            [
                "AND" => [
                    'fl.isDeleted[!]' => 1,
                    'fl.technicalReviewId' => $id,
                ]
            ]
        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    //FILL LEVEL LIST FOR ID

    $group->get('fillLevel/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->select(
            'fill_level',
            '*',
            ['id' => $id]
        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    //FILL LEVEL REGISTRY
    $group->post('fillLevel', function ($request, $response, array $args) {
        $datos = $request->getParsedBody();

        $image_name = $datos['nameImage'];
        $imagePath = $datos['filePath'];
        if ($imagePath) {
            $image_upload_dir = $_SERVER['DOCUMENT_ROOT'] . '/imagePath/' . $image_name;
            $protocol = stripos($_SERVER['SERVER_PROTOCOL'], 'https') === true ? 'https://' : 'http://';
            $imagenUrl = $protocol . $_SERVER['SERVER_NAME'] . '/imagePath/' . $image_name;
        } else {
            $imagenUrl = "";
        }
        $diameter = $datos['diameter'];
        $totalNumberLifters = $datos['totalNumberLifters'];
        $exposedLifter = $datos['exposedLifter'];
        $height = $datos['height'];
        $fillingLevel = $datos['fillingLevel'];
        $description = $datos['description'];
        $technicalReviewId = $datos['technicalReviewId'];

        $datos = $this->get('db')->select(
            'fill_level',
            '*',
            [
                "AND" => [
                    'isDeleted[!]' => 1,
                    'technicalReviewId' => $technicalReviewId
                ]
            ]
        );

        if ($datos) {
            $data = array("Respuesta" => "Datos Existentes");
        } else {

            $data = $this->get('db')->insert('fill_level', [
                "diameter" => $diameter,
                "totalNumberLifters" => $totalNumberLifters,
                "exposedLifter" => $exposedLifter,
                "height" => $height,
                "fillingLevel" => $fillingLevel,
                "description" => $description,
                "technicalReviewId" => $technicalReviewId,
                "imagen" => $imagenUrl,
            ]);
            if ($data) {
                $data = array("Respuesta" => "Registro Exitoso");
                file_put_contents($image_upload_dir, base64_decode($imagePath));
            } else {
                $data = array("Error" => "error");
            }
        }


        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    //FILL LEVEL UPDATE
    $group->put('fillLevel', function ($request, $response, array $args) {
        $datos = $request->getParsedBody();

        $id = $datos['id'];
        $diameter = $datos['diameter'];
        $totalNumberLifters = $datos['totalNumberLifters'];
        $exposedLifter = $datos['exposedLifter'];
        $height = $datos['height'];
        $fillingLevel = $datos['fillingLevel'];
        $description = $datos['description'];

        $data = $this->get('db')->update('fill_level', [
            "diameter" => $diameter,
            "totalNumberLifters" => $totalNumberLifters,
            "exposedLifter" => $exposedLifter,
            "height" => $height,
            "fillingLevel" => $fillingLevel,
            "description" => $description
        ], ["id" => $id]);
        if ($data) {
            $data = array("Respuesta" => "Actualizacion Exitosa");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    //Update imagen
    $group->put('fill_level/image', function ($request, $response, array $args) {
        $datos = $request->getParsedBody();
        $image_name = $datos['nameImage'];
        $imagePath = $datos['filePath'];
        $image_upload_dir = $_SERVER['DOCUMENT_ROOT'] . '/imagePath/' . $image_name;
        $id = $datos['id'];
        $protocol = stripos($_SERVER['SERVER_PROTOCOL'], 'https') === true ? 'https://' : 'http://';
        $imagenUrl = $protocol . $_SERVER['SERVER_NAME'] . '/imagePath/' . $image_name;

        $data = $this->get('db')->update('fill_level', [
            "imagen" => $imagenUrl
        ], ['id' => $id]);

        if ($data) {
            $data = array("Respuesta" => "Se actualizó Correctamente");
            file_put_contents($image_upload_dir, base64_decode($imagePath));
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    //FILL LEVEL DELETE
    $group->delete('fillLevel/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->delete('fill_level', ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "dato eliminado");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });


    //FILL LEVEL LOGICAL DELETE
    $group->put('fillLevel/logicaldelete', function ($request, $response, array $args) {
        $datos = $request->getParsedBody();
        $isDeleted = $datos['isDeleted'];
        $id = $datos['id'];
        $data = $this->get('db')->update('fill_level', [
            "isDeleted" => $isDeleted
        ], ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "Se elimino Correctamente");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });


    //FLASH WEAR LIST TECHNICAL REVIEW

    $group->get('flashwear/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->select(
            'technical_review(tr)',
            [
                '[><]flash_wear(fw)' => ['tr.id' => 'technicalReviewId'],
            ],
            [

                "fw.id",
                "fw.nominalThickness",
                "fw.nominalThickness2",
                "fw.remainingThickness",
                "fw.remainingThickness2",
                "fw.exchangeLimit",
                "fw.exchangeLimit2",
                "fw.monthDay",
                "fw.monthDay2",
                "fw.projection",
                "fw.projection2",
                "fw.installationDate",
                "fw.measurementDate",
                "fw.imagen",
                "fw.description",
                "fw.isDeleted(fwisDeleted)",
                "technicalReviewId" => [
                    "tr.id(idTR)",
                    "tr.title",
                    "tr.content",
                    "tr.conclusions",
                    "tr.status",
                    "tr.isDeleted",
                    "tr.inspectionDate",
                    "tr.equipmentId",
                    "tr.technicalUserId",
                    "tr.supervisorUserId",
                ]

            ],
            [
                "AND" => [
                    'fw.isDeleted[!]' => 1,
                    'fw.technicalReviewId' => $id,
                ]
            ]

        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    //FLASH WEAR LIST TECHNICAL REVIEW

    $group->get('flashwear/all/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->select(
            'flash_wear',
            '*',
            [
                'id' => $id,
            ]

        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });


    //FLASH WEAR REGISTRY
    $group->post('flashwear', function ($request, $response, array $args) {
        $datos = $request->getParsedBody();
        $image_name = $datos['nameImage'];
        $technicalReviewId = $datos['technicalReviewId'];
        $imagePath = $datos['filePath'];
        if ($imagePath) {
            $image_upload_dir = $_SERVER['DOCUMENT_ROOT'] . '/imagePath/' . $image_name;
            $protocol = stripos($_SERVER['SERVER_PROTOCOL'], 'https') === true ? 'https://' : 'http://';
            $imagenUrl = $protocol . $_SERVER['SERVER_NAME'] . '/imagePath/' . $image_name;
        } else {
            $imagenUrl = "";
        }
        $nominalThickness = $datos['nominalThickness'];
        $nominalThickness2 = $datos['nominalThickness2'];
        $remainingThickness = $datos['remainingThickness'];
        $remainingThickness2 = $datos['remainingThickness2'];
        $exchangeLimit = $datos['exchangeLimit'];
        $exchangeLimit2 = $datos['exchangeLimit2'];
        $monthDay = $datos['monthDay'];
        $monthDay2 = $datos['monthDay2'];
        $projection = $datos['projection'];
        $projection2 = $datos['projection2'];
        $installationDate  = $datos['installationDate'];
        $measurementDate = $datos['measurementDate'];
        $description = $datos['description'];
        $technicalReviewId = $datos['technicalReviewId'];

        $datos = $this->get('db')->select(
            'flash_wear',
            '*',
            [
                "AND" => [
                    'isDeleted[!]' => 1,
                    'technicalReviewId' => $technicalReviewId
                ]
            ]
        );

        if ($datos) {
            $data = array("Respuesta" => "Datos Existentes");
        } else {

            $data = $this->get('db')->insert('flash_wear', [
                "nominalThickness" => $nominalThickness,
                "nominalThickness2" => $nominalThickness2,
                "remainingThickness" => $remainingThickness,
                "remainingThickness2" => $remainingThickness2,
                "exchangeLimit" => $exchangeLimit,
                "exchangeLimit2" => $exchangeLimit2,
                "monthDay" => $monthDay,
                "monthDay2" => $monthDay2,
                "projection" => $projection,
                "projection2" => $projection2,
                "installationDate" => $installationDate,
                "measurementDate" => $measurementDate,
                "imagen" => $imagenUrl,
                "description" => $description,
                "technicalReviewId" => $technicalReviewId,
            ]);
            if ($data) {
                $data = array("Respuesta" => "Registro Exitoso");
                file_put_contents($image_upload_dir, base64_decode($imagePath));
            } else {
                $data = array("Error" => "error");
            }
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    //FLASH WEAR UPDATE image
    $group->put('flashwear/image', function ($request, $response, array $args) {
        $datos = $request->getParsedBody();
        $image_name = $datos['nameImage'];
        $imagePath = $datos['filePath'];
        $image_upload_dir = $_SERVER['DOCUMENT_ROOT'] . '/imagePath/' . $image_name;
        $id = $datos['id'];
        $protocol = stripos($_SERVER['SERVER_PROTOCOL'], 'https') === true ? 'https://' : 'http://';
        $imagenUrl = $protocol . $_SERVER['SERVER_NAME'] . '/imagePath/' . $image_name;

        $data = $this->get('db')->update('flash_wear', [
            "imagen" => $imagenUrl
        ], ['id' => $id]);

        if ($data) {
            $data = array("Respuesta" => "Se actualizó Correctamente");
            file_put_contents($image_upload_dir, base64_decode($imagePath));
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    //FLASH WEAR UPDATE
    $group->put('flashwear', function ($request, $response, array $args) {
        $datos = $request->getParsedBody();

        $id = $datos['id'];

        $nominalThickness = $datos['nominalThickness'];
        $nominalThickness2 = $datos['nominalThickness2'];
        $remainingThickness = $datos['remainingThickness'];
        $remainingThickness2 = $datos['remainingThickness2'];
        $exchangeLimit = $datos['exchangeLimit'];
        $exchangeLimit2 = $datos['exchangeLimit2'];
        $monthDay = $datos['monthDay'];
        $monthDay2 = $datos['monthDay2'];
        $projection = $datos['projection'];
        $projection2 = $datos['projection2'];
        $installationDate  = $datos['installationDate'];
        $measurementDate = $datos['measurementDate'];
        $description = $datos['description'];

        $data = $this->get('db')->update('flash_wear', [
            "nominalThickness" => $nominalThickness,
            "nominalThickness2" => $nominalThickness2,
            "remainingThickness" => $remainingThickness,
            "remainingThickness2" => $remainingThickness2,
            "exchangeLimit" => $exchangeLimit,
            "exchangeLimit2" => $exchangeLimit2,
            "monthDay" => $monthDay,
            "monthDay2" => $monthDay2,
            "projection" => $projection,
            "projection2" => $projection2,
            "installationDate" => $installationDate,
            "measurementDate" => $measurementDate,
            "description" => $description
        ], ["id" => $id]);

        if ($data) {
            $data = array("Respuesta" => "Actualizacion Exitosa");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });


    //FLASH WEAR DELETE
    $group->delete('flashwear/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->delete('flash_wear', ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "dato eliminado");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });


    //FLASH WEAR LOGICAL DELETE
    $group->put('flashwear/logicaldelete', function ($request, $response, array $args) {
        $datos = $request->getParsedBody();
        $isDeleted = $datos['isDeleted'];
        $id = $datos['id'];

        $data = $this->get('db')->update('flash_wear', [
            "isDeleted" => $isDeleted
        ], ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "Se elimino Correctamente");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    $group->get('user', function ($request, $response, array $args) {
        $data = $this->get('db')->select(
            'user(u)',
            [
                '[><]document_type(d)' => ['u.documentTypeId' => 'id']
            ],
            [
                'u.id',
                'u.Name',
                'u.email',
                'u.password',
                'u.isDeleted',
                'u.rol',
                'u.ndocument',
                'u.estado',
                "documentTypeId" => [
                    "d.id(id_documentType)",
                    "d.name",
                    "d.isDeleted(isDeleteddocumentType)",
                ]

            ],
            [
                //'u.isDeleted[!]' => 1,
                "ORDER" => ["u.id" => "DESC"]
            ]

        );


        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    /* usuario por rol */
    $group->get('user/rol/{rol}', function ($request, $response, array $args) {
        $rol = $args['rol'];
        $data = $this->get('db')->select(
            'user(u)',
            [
                '[><]document_type(d)' => ['u.documentTypeId' => 'id']
            ],
            [
                'u.id',
                'u.Name',
                'u.email',
                'u.password',
                'u.isDeleted',
                'u.rol',
                'u.ndocument',
                "documentTypeId" => [
                    "d.id(id_documentType)",
                    "d.name",
                    "d.isDeleted(isDeleteddocumentType)",
                ]

            ],
            [
                "AND" => [
                    'u.isDeleted[!]' => 1,
                    'u.rol' => $rol,
                ]
            ]

        );


        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    $group->get('user/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->select(
            'user(u)',
            [
                '[><]document_type(d)' => ['u.documentTypeId' => 'id']
            ],
            [
                'u.id',
                'u.Name',
                'u.email',
                'u.password',
                'u.isDeleted',
                'u.rol',
                'u.ndocument',
                'u.imagePath',
                'u.estado',
                "documentTypeId" => [
                    "d.id(id_documentType)",
                    "d.name",
                    "d.isDeleted(isDeleteddocumentType)",
                ]

            ],
            ['u.id' =>  $id]
        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    $group->post('newuser', function ($request, $response, array $args) {
        $daatos = $request->getParsedBody();
        $valor1 = $daatos['Name'];
        $valor2 = $daatos['email'];
        $valor3 = $daatos['password'];
        $encryp = Encriptacion::encryption($valor3);
        $valor4 = $daatos['rol'];
        $valor5 = $daatos['documentTypeId'];
        $valor6 = $daatos['ndocument'];

        $correorepete = $this->get('db')->select(
            'user(u)',
            '*',
            ['u.email' => $valor2]

        );

        if ($correorepete) {
            $data = array("Respuesta" => "Correo repeat");
        } else {
            $data = $this->get('db')->insert('user', [
                "Name" => $valor1,
                "email" => $valor2,
                "password" => $encryp,
                "rol" => $valor4,
                "documentTypeId" => $valor5,
                'ndocument' => $valor6
            ]);
            if ($data) {
                $data = array("Respuesta" => "Registro Exitoso");
            } else {
                $data = array("Error" => "error");
            }
        }

        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    $group->put('updateuser', function ($request, $response, array $args) {
        $daatos = $request->getParsedBody();
        $valor1 = $daatos['Name'];
        $valor2 = $daatos['email'];
        $valor3 = $daatos['password'];
        $encryp = Encriptacion::encryption($valor3);
        $valor4 = $daatos['rol'];
        $valor5 = $daatos['documentTypeId'];
        $valor6 = $daatos['ndocument'];
        $estado = $daatos['estado'];
        $valor8 = $daatos['id'];
        if ($estado == "Activo") {
            $isdelete = 0;
        } else {
            $isdelete = 1;
        }
        if ($valor3 == "" || $valor3 == null) {

            $data = $this->get('db')->update(
                'user',
                [
                    "Name" => $valor1,
                    "rol" => $valor4,
                    "documentTypeId" => $valor5,
                    'ndocument' => $valor6,
                    "isDeleted" => $isdelete,
                    'estado' => $estado
                ],
                ['id' => $valor8]
            );
        } else {
            $data = $this->get('db')->update(
                'user',
                [
                    "Name" => $valor1,
                    "email" => $valor2,
                    "password" => $encryp,
                    "rol" => $valor4,
                    "documentTypeId" => $valor5,
                    'ndocument' => $valor6,
                    "isDeleted" => $isdelete,
                    'estado' => $estado
                ],
                ['id' => $valor8]
            );
        }
        if ($data) {
            $data = array("Respuesta" => "Se actualizó Correctamente");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    $group->put('updateuserperfil', function ($request, $response, array $args) {
        $daatos = $request->getParsedBody();
        $valor1 = $daatos['Name'];
        $valor2 = $daatos['email'];
        $valor5 = $daatos['documentTypeId'];
        $valor6 = $daatos['ndocument'];
        $valor8 = $daatos['id'];
        $data = $this->get('db')->update(
            'user',
            [
                "Name" => $valor1,
                "email" => $valor2,
                "documentTypeId" => $valor5,
                'ndocument' => $valor6
            ],
            ['id' => $valor8]
        );
        if ($data) {
            $data = array("Respuesta" => "Se actualizó Correctamente");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->put('updateuserImageperfil', function ($request, $response, array $args) {

        $daatos = $request->getParsedBody();
        $image_name = $daatos['nameImage'];
        $imagePath = $daatos['imagePath'];
        $image_upload_dir = $_SERVER['DOCUMENT_ROOT'] . '/imagePath/' . $image_name;
        $protocol = stripos($_SERVER['SERVER_PROTOCOL'], 'https') === true ? 'https://' : 'http://';
        $imagenUrl = $protocol . $_SERVER['SERVER_NAME'] . '/imagePath/' . $image_name;
        $id = $daatos['id'];
        $data = $this->get('db')->update(
            'user',
            [
                'imagePath' => $imagenUrl
            ],
            ['id' => $id]
        );
        if ($data) {
            $data = array("Respuesta" => "Se actualizó Correctamente");
            file_put_contents($image_upload_dir, base64_decode($imagePath));
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->put('logicdeleteuser', function ($request, $response, array $args) {
        $daatos = $request->getParsedBody();
        $valor = $daatos['id'];
        $data = $this->get('db')->update(
            'user',
            [

                "isDeleted" => '1',
                "estado" => 'Inactivo'

            ],
            ['id' => $valor]
        );
        if ($data) {
            $data = array("Respuesta" => "Se elimino Correctamente");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    $group->delete('deleteuser/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->delete('user', ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "dato eliminado");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });


    // DOCUMENT_TYPE
    $group->get('document_type', function ($request, $response, array $args) {
        $data = $this->get('db')->select(
            'document_type(u)',
            '*',
            [
                'isDeleted[!]' => 1,
                "ORDER" => ["id" => "DESC"]
            ]
        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->get('document_type/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->select(
            'document_type(u)',
            '*',
            ['id' =>  $id]
        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    $group->post('newdocument_type', function ($request, $response, array $args) {
        $daatos = $request->getParsedBody();
        $valor1 = $daatos['name'];
        $valor2 = $daatos['isDeleted'];

        $data = $this->get('db')->insert('document_type', [
            "name" => $valor1,
            "isDeleted" => $valor2
        ]);
        if ($data) {
            $data = array("Respuesta" => "Registro Exitoso");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    $group->put('updatedocument_type', function ($request, $response, array $args) {
        $daatos = $request->getParsedBody();
        $valor1 = $daatos['name'];
        $valor2 = $daatos['isDeleted'];
        $valor3 = $daatos['id'];
        $data = $this->get('db')->update(
            'document_type',
            [
                "name" => $valor1,
                "isDeleted" => $valor2
            ],
            ['id' => $valor3]
        );
        if ($data) {
            $data = array("Respuesta" => "Se actualizó Correctamente");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    $group->put('deletedocument_type', function ($request, $response, array $args) {
        $daatos = $request->getParsedBody();
        $valor = $daatos['id'];
        $data = $this->get('db')->update(
            'document_type',
            [
                "isDeleted" => '1'
            ],
            ['id' => $valor]
        );
        if ($data) {
            $data = array("Respuesta" => "Se elimino Correctamente");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    $group->delete('deletedocument_type/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->delete('document_type', ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "dato eliminado");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    /* List employee  company*/
    $group->get('employees/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->select(
            'company_employees(cuu)',
            [
                '[><]document_type(d)' => ['cuu.documentTypeId' => 'id']
            ],
            [
                'cuu.id(id_empl)',
                'cuu.Name',
                "documentTypeId" => [
                    "d.id(documentType)",
                    "d.name(name_documentType)",
                    "d.isDeleted(idDeleteddocumentType)",
                ],
                'cuu.document',
                'cuu.email',
                'cuu.phone',
                'cuu.rol',
                'cuu.estado',
                'cuu.isDeleted(isDeleted_emp)',

            ],
            [
                'cuu.id' =>  $id
            ]
        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    /* List employee  company*/
    $group->get('company/employee/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->select(
            'company_employees(cuu)',
            [
                '[><]document_type(d)' => ['cuu.documentTypeId' => 'id']
            ],
            [
                'cuu.id(id_empl)',
                'cuu.name',
                "documentTypeId" => [
                    "d.id(documentType)",
                    "d.name(name_documentType)",
                    "d.isDeleted(idDeleteddocumentType)",
                ],
                'cuu.document',
                'cuu.email',
                'cuu.phone',
                'cuu.rol',
                'cuu.estado',
                'cuu.isDeleted(isDeleted_emp)',

            ],
            [
                "AND" => [
                    'cuu.companyId' =>  $id
                ],
                "ORDER" => ["cuu.id" => "DESC"]
            ]
        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    /*api para pa app */
    $group->get('company/employeeId/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->select(
            'company_employees(cuu)',
            [
                '[><]document_type(d)' => ['cuu.documentTypeId' => 'id']
            ],
            [
                'cuu.id(id_empl)',
                'cuu.name',
                "documentTypeId" => [
                    "d.id(documentType)",
                    "d.name(name_documentType)",
                    "d.isDeleted(idDeleteddocumentType)",
                ],
                'cuu.document',
                'cuu.email',
                'cuu.phone',
                'cuu.rol',
                'cuu.estado',
                'cuu.isDeleted(isDeleted_emp)',

            ],
            [
                "AND" => [
                    'cuu.id' =>  $id
                ],
                "ORDER" => ["cuu.id" => "DESC"]
            ]
        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    /* List employee  company*/
    $group->get('company/employee/select/{rol}/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $rol = $args['rol'];
        $data = $this->get('db')->select(
            'company_employees(cuu)',
            [
                '[><]document_type(d)' => ['cuu.documentTypeId' => 'id']


            ],
            [


                'cuu.id(id_empl)',
                'cuu.Name',
                "documentTypeId" => [
                    "d.id(documentType)",
                    "d.name(name_documentType)",
                    "d.isDeleted(idDeleteddocumentType)",
                ],
                'cuu.document',
                'cuu.email',
                'cuu.phone',
                'cuu.rol',
                'cuu.estado',
                'cuu.isDeleted(isDeleted_emp)',

            ],
            [
                "AND" => [
                    'cuu.companyId' =>  $id,
                    'cuu.isDeleted[!]' => 1,
                    'cuu.rol' => $rol
                ],
                "ORDER" => ["cuu.id" => "DESC"]
            ]
        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    /* new employee  */
    $group->post('company/employee', function ($request, $response, array $args) {
        $daatos = $request->getParsedBody();
        $name = $daatos['name'];
        $documentTypeId = $daatos['documentTypeId'];
        $document = $daatos['document'];
        $email = $daatos['email'];
        $phone     = $daatos['phone'];
        $rol = $daatos['rol'];
        $companyId = $daatos['companyId'];

        $data = $this->get('db')->insert('company_employees', [
            "name" => $name,
            "documentTypeId" => $documentTypeId,
            "document" => $document,
            "email" => $email,
            "phone" => $phone,
            "rol" => $rol,
            "companyId" => $companyId
        ]);
        if ($data) {
            $data = array("Respuesta" => "Registro Exitoso");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    /* update company emplotee */
    $group->put('company/employee', function ($request, $response, array $args) {
        $daatos = $request->getParsedBody();
        $name = $daatos['name'];
        $documentTypeId = $daatos['documentTypeId'];
        $document = $daatos['document'];
        $email = $daatos['email'];
        $phone     = $daatos['phone'];
        $rol = $daatos['rol'];
        $estado = $daatos['estado'];
        $id = $daatos['id'];
        if ($estado == "Activo") {
            $isdelete = 0;
        } else {
            $isdelete = 1;
        }

        $data = $this->get('db')->update('company_employees', [
            "name" => $name,
            "documentTypeId" => $documentTypeId,
            "document" => $document,
            "email" => $email,
            "phone" => $phone,
            "rol" => $rol,
            "isDeleted" => $isdelete,
            "estado" => $estado
        ], ['id' => $id]);

        if ($data) {
            $data = array("Respuesta" => "Se actualizó Correctamente");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });


    $group->put('company/employee/logicaldelete', function ($request, $response, array $args) {
        $datos = $request->getParsedBody();
        $isDeleted = $datos['isDeleted'];
        $id = $datos['id'];

        $data = $this->get('db')->update('company_employees', [
            "isDeleted" => $isDeleted,
            "estado" => 'Inactivo'
        ], ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "Se elimino Correctamente");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    $group->get('detailstechnicalreview/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->select(
            'technical_review(tr)',
            [
                '[>]fill_level(fl)' => ['tr.id' => 'technicalReviewId'],
                '[>]flash_wear(fw)' => ['tr.id' => 'technicalReviewId'],
                '[>]file_technical(ft)' => ['tr.id' => 'technicalReviewId'],
            ],
            [
                "tr.id",
                "tr.title",
                "tr.content",
                "tr.conclusions",
                "tr.status",
                "tr.isDeleted",
                "tr.inspectionDate",
                "tr.equipmentId",
                "tr.technicalUserId",
                "tr.supervisorUserId",
                "fill_level" => [
                    "fl.id(idfill_level)",
                    "fl.diameter",
                    "fl.totalNumberLifters",
                    "fl.exposedLifter",
                    "fl.height",
                    "fl.fillingLevel",
                    "fl.isDeleted(isDeletedfill_level)",
                    "fl.fillingLevel",
                    "fl.description",
                    "fl.technicalReviewId(technicalReviewIdfill_level)"
                ],
                "flash_wear" => [
                    "fw.id(idflash_wear)",
                    "fw.nominalThickness",
                    "fw.remainingThickness",
                    "fw.exchangeLimit",
                    "fw.monthDay",
                    "fw.projection",
                    "fw.installationDate",
                    "fw.measurementDate",
                    "fw.isDeleted(isDeletedflash_wear)",
                    "fw.technicalReviewId(technicalReviewIdflash_wear)"
                ],
                "file_technical" => [
                    "ft.id(idfile_technical)",
                    "ft.filePath",
                    "ft.isDeleted",
                    "ft.technicalReviewId(technicalReviewIdfile_technical)"
                ],
            ],
            [
                'tr.id' => $id
            ]

        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    /* all technical review */
    $group->get('detailstechnicalreviewall/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->select(
            'technical_review(tr)',
            [
                '[><]equipment(eq)' => ['tr.equipmentId' => 'id'],
                '[><]company(c)' => ['eq.companyId' => 'id'],
                '[>]company_employees(ce)' => ['tr.supervisorUserId' => 'id'],
                '[>]company_employees(cem)' => ['tr.supervisorMinId' => 'id'],
                '[>]fill_level(fl)' => ['tr.id' => 'technicalReviewId'],
                '[>]flash_wear(fw)' => ['tr.id' => 'technicalReviewId'],
                '[>]user(u)' => ['tr.technicalUserId' => 'id'],
            ],
            [
                "tr.id",
                "tr.title",
                "tr.content",
                "tr.conclusions",
                "tr.status",
                "tr.isDeleted",
                "tr.inspectionDate",
                "tr.equipmentId",
                "tr.technicalUserId",
                "tr.supervisorUserId",
                "tr.target",
                "tr.pathPdf",
                "fill_level" => [
                    "fl.id(idfill_level)",
                    "fl.diameter",
                    "fl.totalNumberLifters",
                    "fl.exposedLifter",
                    "fl.height",
                    "fl.fillingLevel",
                    "fl.description",
                    "fl.imagen(imagenfl)",
                    "fl.isDeleted(isDeletedfill_level)",
                    "fl.technicalReviewId(technicalReviewIdfill_level)"
                ],
                "flash_wear" => [
                    "fw.id(idflash_wear)",
                    "fw.nominalThickness",
                    "fw.nominalThickness2",
                    "fw.remainingThickness",
                    "fw.remainingThickness2",
                    "fw.exchangeLimit",
                    "fw.exchangeLimit2",
                    "fw.monthDay",
                    "fw.monthDay2",
                    "fw.projection",
                    "fw.projection2",
                    "fw.installationDate",
                    "fw.measurementDate",
                    "fw.description",
                    "fw.imagen(imagenfw)",
                    "fw.isDeleted(isDeletedflash_wear)",
                    "fw.technicalReviewId(technicalReviewIdflash_wear)"
                ],
                "equipment" => [
                    "eq.id(idequip)",
                    "eq.description(desequip)",
                    "eq.code",
                    "eq.isDeleted(isDequip)",
                    "eq.estado(estadoEq)",
                    "companyId" => [
                        "c.id(idcompany)",
                        "c.name",
                        "c.description(companydescription)",
                        "c.isDeleted(companyisDeleted)",
                        "c.ruc",
                        "c.headquarter",
                    ],
                ],
                "emplJCM" => [
                    'ce.id(id_emplJ)',
                    'ce.Name(nameempJ)',
                    'ce.document(docempJ)',
                    'ce.email(mailempJ)',
                    'ce.phone(phoneempJ)',
                    'ce.rol(rolempJ)',
                    'ce.estado(estadoempJ)',
                    'ce.isDeleted(isDeleted_empJ)',

                ],
                "emplMIN" => [
                    'cem.id(id_emplM)',
                    'cem.Name(nameempM)',
                    'cem.document(docempM)',
                    'cem.email(mailempM)',
                    'cem.phone(phoneempM)',
                    'cem.rol(rolempM)',
                    'cem.estado(estadoempM)',
                    'cem.isDeleted(isDeleted_empM)',
                ],
                "user" => [
                    "u.id(idU)",
                    "u.Name(NameU)",
                ]
            ],
            [
                'tr.id' => $id
            ]

        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    $group->post('detailstechnicalreviewall/imagen', function ($request, $response, array $args) {
        $datos = $request->getParsedBody();
        $image_name = $datos['nameImage'];
        $technicalReviewId = $datos['technicalReviewId'];
        $imagePath = $datos['filePath'];
        if ($imagePath) {
            $image_upload_dir = $_SERVER['DOCUMENT_ROOT'] . '/imagePath/' . $image_name;
            $protocol = stripos($_SERVER['SERVER_PROTOCOL'], 'https') === true ? 'https://' : 'http://';
            $imagenUrl = $protocol . $_SERVER['SERVER_NAME'] . '/imagePath/' . $image_name;
        } else {
            $imagenUrl = "";
        }
        $data = $this->get('db')->insert('file_technical', [
            "filePath" => $imagenUrl,
            "technicalReviewId" => $technicalReviewId
        ]);

        if ($data) {
            $data = array("Respuesta" => "Registro Exitoso");
            file_put_contents($image_upload_dir, base64_decode($imagePath));
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    $group->put('file_technical/updateimage', function ($request, $response, array $args) {
        $datos = $request->getParsedBody();
        $image_name = $datos['nameImage'];
        $imagePath = $datos['filePath'];
        $image_upload_dir = $_SERVER['DOCUMENT_ROOT'] . '/imagePath/' . $image_name;
        $id = $datos['id'];
        $protocol = stripos($_SERVER['SERVER_PROTOCOL'], 'https') === true ? 'https://' : 'http://';
        $imagenUrl = $protocol . $_SERVER['SERVER_NAME'] . '/imagePath/' . $image_name;
        $data = $this->get('db')->update('file_technical', [
            "filePath" => $imagenUrl
        ], ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "Se actualizó Correctamente");
            file_put_contents($image_upload_dir, base64_decode($imagePath));
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    $group->delete('file_technical/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $datos = $request->getParsedBody();
        $nameImagen = $datos['filePath'];
        $protocol = stripos($_SERVER['SERVER_PROTOCOL'], 'https') === true ? 'https://' : 'http://';
        $imagenUrl = $protocol . $_SERVER['SERVER_NAME'] . '/imagePath/';
        $newDato =  str_replace($imagenUrl, "", $nameImagen);
        $data = $this->get('db')->delete('file_technical', ['id' => $id]);
        if ($data) {
            $data = array("Respuesta" => "dato eliminado");
            unlink("imagePath/$newDato");
        } else {
            $data = array("Error" => "error");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    //actualizacion de estado en progreso
    $group->put('update/status/inprogress', function ($request, $response, array $args) {
        $datos = $request->getParsedBody();
        $technicalReviewId = $datos['technicalReviewId'];
        $imagenes = $this->get('db')->select(
            'file_technical',
            '*',
            [
                'technicalReviewId' => $technicalReviewId
            ]
        );

        if (count($imagenes) < 3) {
            $data = array("Respuesta" => "insuficiente");
        } else if (count($imagenes) > 6) {
            $data = array("Respuesta" => "excede");
        } else {
            $desgaste = $this->get('db')->select(
                'flash_wear',
                '*',
                [
                    "AND" => [
                        'technicalReviewId' => $technicalReviewId,
                        'isDeleted[!]' => 1
                    ]
                ]
            );
            if (count($desgaste) == 0) {
                $data = array("Respuesta" => "desgaste insuficiente");
            } else {

                $llenado = $this->get('db')->select(
                    'fill_level',
                    '*',
                    [
                        "AND" => [
                            'technicalReviewId' => $technicalReviewId,
                            'isDeleted[!]' => 1
                        ]
                    ]
                );
                if (count($llenado) == 0) {
                    $data = array("Respuesta" => "llenado insuficiente");
                } else {

                    $data = $this->get('db')->update('technical_review', [
                        "status" => "EN PROGRESO",
                    ], ['id' => $technicalReviewId]);
                    if ($data) {
                        $data = array("Respuesta" => "Se guardo Correctamente");
                    } else {
                        $data = array("Error" => "error");
                    }
                }
            }
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    //actualizacion de estado en progreso
    $group->put('update/status/technical', function ($request, $response, array $args) {
        $datos = $request->getParsedBody();
        $technicalReviewId = $datos['technicalReviewId'];
        $status = $datos['status'];
        $data = $this->get('db')->update('technical_review', [
            "status" => $status,
        ], ['id' => $technicalReviewId]);

        if ($data) {
            $data = array("Respuesta" => "exito");
        } else {
            $data = array("Error" => "error");
        }

        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    //revisiones de equipo anteriores
    $group->get('technicalreview/pastreviews/{equipo}/{empresa}/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $equipo = $args['equipo'];
        $empresa = $args['empresa'];
        $data = $this->get('db')->query(
            "SELECT tr.inspectionDate,fl.* FROM technical_review tr inner join equipment e on tr.equipmentId=e.id inner join company c on e.companyId=c.id inner join flash_wear fl on tr.id=fl.technicalReviewId where tr.equipmentId=$equipo and c.id=$empresa and tr.status= 'COMPLETADO' and tr.isDeleted = 0 and tr.id !=$id order by tr.id DESC limit 2;"
        )->fetchAll();

        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    //Almacenar pdf a la carpeta reportes
    $group->get('detailstechnicalreviewallpdf/{id}/{equipo}/{empresa}', function ($request, $response, array $args) {
        $id = $args['id'];
        $equipo = $args['equipo'];
        $empresa = $args['empresa'];
        $data = $this->get('db')->select(
            'technical_review(tr)',
            [
                '[><]equipment(eq)' => ['tr.equipmentId' => 'id'],
                '[><]company(c)' => ['eq.companyId' => 'id'],
                '[><]company_employees(ce)' => ['tr.supervisorUserId' => 'id'],
                '[><]company_employees(cem)' => ['tr.supervisorMinId' => 'id'],
                '[>]fill_level(fl)' => ['tr.id' => 'technicalReviewId'],
                '[>]flash_wear(fw)' => ['tr.id' => 'technicalReviewId'],
                '[>]user(u)' => ['tr.technicalUserId' => 'id'],
            ],
            [
                "tr.id",
                "tr.title",
                "tr.content",
                "tr.conclusions",
                "tr.status",
                "tr.isDeleted",
                "tr.inspectionDate",
                "tr.equipmentId",
                "tr.technicalUserId",
                "tr.supervisorUserId",
                "tr.target",
                "fill_level" => [
                    "fl.id(idfill_level)",
                    "fl.diameter",
                    "fl.totalNumberLifters",
                    "fl.exposedLifter",
                    "fl.height",
                    "fl.fillingLevel",
                    "fl.description",
                    "fl.imagen(Imagenfl)",
                    "fl.isDeleted(isDeletedfill_level)",
                    "fl.technicalReviewId(technicalReviewIdfill_level)"
                ],
                "flash_wear" => [
                    "fw.id(idflash_wear)",
                    "fw.nominalThickness",
                    "fw.nominalThickness2",
                    "fw.remainingThickness",
                    "fw.remainingThickness2",
                    "fw.exchangeLimit",
                    "fw.exchangeLimit2",
                    "fw.monthDay",
                    "fw.monthDay2",
                    "fw.projection",
                    "fw.projection2",
                    "fw.installationDate",
                    "fw.measurementDate",
                    "fw.description",
                    "fw.imagen",
                    "fw.isDeleted(isDeletedflash_wear)",
                    "fw.technicalReviewId(technicalReviewIdflash_wear)"
                ],
                "equipment" => [
                    "eq.id(idequip)",
                    "eq.description(desequip)",
                    "eq.code",
                    "eq.isDeleted(isDequip)",
                    "eq.estado(estadoEq)",
                    "companyId" => [
                        "c.id(idcompany)",
                        "c.name",
                        "c.description(companydescription)",
                        "c.isDeleted(companyisDeleted)",
                        "c.ruc",
                        "c.headquarter",
                    ],
                ],
                "emplJCM" => [
                    'ce.id(id_emplJ)',
                    'ce.Name(nameempJ)',
                    'ce.document(docempJ)',
                    'ce.email(mailempJ)',
                    'ce.phone(phoneempJ)',
                    'ce.rol(rolempJ)',
                    'ce.estado(estadoempJ)',
                    'ce.isDeleted(isDeleted_empJ)',

                ],
                "emplMIN" => [
                    'cem.id(id_emplM)',
                    'cem.Name(nameempM)',
                    'cem.document(docempM)',
                    'cem.email(mailempM)',
                    'cem.phone(phoneempM)',
                    'cem.rol(rolempM)',
                    'cem.estado(estadoempM)',
                    'cem.isDeleted(isDeleted_empM)',
                ],
                "user" => [
                    "u.id(idU)",
                    "u.Name(NameU)",
                ]
            ],
            [
                'tr.id' => $id
            ]

        );
        $Imagenes = $this->get('db')->select(
            'technical_review(tr)',
            [
                '[><]file_technical(ft)' => ['tr.id' => 'technicalReviewId']
            ],
            [
                "ft.id",
                "ft.isDeleted(ftisDelete)",
                "ft.filePath(ftfilePath)",
                "ft.fecha",
                "technicalReviewId" => [
                    "tr.id(idTR)",
                    "tr.title",
                    "tr.content",
                    "tr.conclusions",
                    "tr.status",
                    "tr.isDeleted",
                    "tr.inspectionDate",
                    "tr.equipmentId",
                    "tr.technicalUserId",
                    "tr.supervisorUserId",
                ]
            ],
            [
                "AND" => [
                    'ft.technicalReviewId' => $id
                ]
            ]
        );
        $RevisionesPasadas = $this->get('db')->query(
            "SELECT tr.inspectionDate,fl.* FROM technical_review tr inner join equipment e on tr.equipmentId=e.id inner join company c on e.companyId=c.id inner join flash_wear fl on tr.id=fl.technicalReviewId where tr.equipmentId=$equipo and c.id=$empresa and tr.status= 'COMPLETADO' and tr.isDeleted = 0 and tr.id !=$id order by tr.id DESC limit 2;"
        )->fetchAll();

        if (count($Imagenes) == 3) {
            $imagepdf = ' 
            <tr>
                <td> <img src="' . $Imagenes[0]['ftfilePath'] . '" style="width:70%;margin-bottom:10px;"></td>
                <td> <img src="' . $Imagenes[1]['ftfilePath'] . '" style="width:70%;margin-bottom:10px;"></td>
                <td> <img src="' . $Imagenes[2]['ftfilePath'] . '" style="width:70%;margin-bottom:10px;"></td>                       
            </tr>';
        } else if (count($Imagenes) == 4) {
            $imagepdf = ' 
            <tr>
                <td> <img src="' . $Imagenes[0]['ftfilePath'] . '" style="width:70%;margin-bottom:10px;"></td>
                <td> <img src="' . $Imagenes[1]['ftfilePath'] . '" style="width:70%;margin-bottom:10px;"></td>
                <td> <img src="' . $Imagenes[2]['ftfilePath'] . '" style="width:70%;margin-bottom:10px;"></td>                       
            </tr>
            <tr>
                <td> <img src="' . $Imagenes[3]['ftfilePath'] . '" style="width:70%;margin-bottom:10px;"></td>
            </tr>
            ';
        } else if (count($Imagenes) == 5) {
            $imagepdf = ' 
            <tr>
                <td> <img src="' . $Imagenes[0]['ftfilePath'] . '" style="width:70%;margin-bottom:10px;"></td>
                <td> <img src="' . $Imagenes[1]['ftfilePath'] . '" style="width:70%;margin-bottom:10px;"></td>
                <td> <img src="' . $Imagenes[2]['ftfilePath'] . '" style="width:70%;margin-bottom:10px;"></td>                       
            </tr>
            <tr>
                <td> <img src="' . $Imagenes[3]['ftfilePath'] . '" style="width:70%;margin-bottom:10px;"></td>
                <td> <img src="' . $Imagenes[4]['ftfilePath'] . '" style="width:70%;margin-bottom:10px;"></td>
            </tr>
            ';
        } else {
            $imagepdf = ' 
            <tr>
                <td> <img src="' . $Imagenes[0]['ftfilePath'] . '" style="width:70%;margin-bottom:10px;"></td>
                <td> <img src="' . $Imagenes[1]['ftfilePath'] . '" style="width:70%;margin-bottom:10px;"></td>
                <td> <img src="' . $Imagenes[2]['ftfilePath'] . '" style="width:70%;margin-bottom:10px;"></td>                       
            </tr>
            <tr>
                <td> <img src="' . $Imagenes[3]['ftfilePath'] . '" style="width:70%;margin-bottom:10px;"></td>
                <td> <img src="' . $Imagenes[4]['ftfilePath'] . '" style="width:70%;margin-bottom:10px;"></td>
                <td> <img src="' . $Imagenes[5]['ftfilePath'] . '" style="width:70%;margin-bottom:10px;"></td>
            </tr>
            ';
        }

        function convertirfecha($cadena)
        {
            $string = substr($cadena, 0, -6);
            $fecha = new DateTime($string);
            $fechafinal = $fecha->format('d-m-Y');
            return $fechafinal;
        }
        function convertirfechanormal($cadena2)
        {
            $fecha2 = new DateTime($cadena2);
            $fechafinal2 = $fecha2->format('d-m-Y');
            return $fechafinal2;
        }
        /* fechas */
        $fechainspeccion = convertirfecha($data[0]['inspectionDate']);
        $installationDate = convertirfechanormal($data[0]['flash_wear']['installationDate']);
        $measurementDate = convertirfechanormal($data[0]['flash_wear']['measurementDate']);
        $projection = convertirfechanormal($data[0]['flash_wear']['projection']);
        $projection2 = convertirfechanormal($data[0]['flash_wear']['projection2']);

        if ($data[0]['status'] == 'COMPLETADO') {
            $mpdf = new \Mpdf\Mpdf(['format' => 'Legal']);
            $stylesheet = file_get_contents('css/estiloPDFMaster.css');
            $mpdf->WriteHTML($stylesheet, \Mpdf\HTMLParserMode::HEADER_CSS);

            $pdfcontent = '
                <body>
                    <table class="cuerpo" style="padding: 1em; border: 10px solid #0046f7;">
                        <thead>
                            <tr style="border: 5px solid #0046f7;">
                                <td colspan="3">
                                    <table>
                                        <tbody>
                                            <tr>
                                                <td style="text-align: left;"><img src="images/logoGate.png"  width="600" height="400"></td>
                                                <td style="text-align: right;font-size: 3rem;font-weight: bold;">REPORTE TÉCNICO</td>
                                                <td width="36%" style="text-align: right;font-size: 1.5rem;color:grey";font-weight: bold;></td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </td>
                            </tr>
                        </thead>
                        <tbody>            
                            <tr style="border: 5px solid #0046f7;">
                                <td>
                                    <table>
                                        <tbody>
                                            <tr>
                                                <td style="text-align: left;border: 5px solid #0046f7;background: #018fd5;color: #fff;font-size: 1.8rem;font-weight: bold;">Minera</td>
                                                <td style="border: 5px solid #0046f7;font-size: 1.8rem;font-weight: bold;">' . $data[0]['equipment']['companyId']['name'] . '</td>
                                            </tr>
                                            <tr>
                                                <td style="text-align: left;border: 5px solid #0046f7;background: #018fd5;color: #fff;font-size: 1.8rem;font-weight: bold;">Equipo</td>
                                                <td style="border: 5px solid #0046f7;font-size: 1.8rem;font-weight: bold;">' . $data[0]['equipment']['desequip'] . '</td>
                                            </tr>
                                            <tr>
                                                <td style="text-align: left;border: 5px solid #0046f7;background: #018fd5;color: #fff;font-size: 1.8rem;font-weight: bold;">Supervisor JCM</td>
                                                <td style="border: 5px solid #0046f7;font-size: 1.8rem;font-weight: bold;">' . $data[0]['emplJCM']['nameempJ'] . '</td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </td>
                                <td colspan="2">
                                    <table>
                                        <tbody>
                                            <tr>
                                                <td style="text-align: left;border: 5px solid #0046f7;background: #018fd5;color: #fff;font-size: 1.8rem;font-weight: bold;">Fecha</td>
                                                <td style="border: 5px solid #0046f7;font-size: 1.8rem;font-weight: bold;">' . $fechainspeccion . '</td>
                                            </tr>
                                            <tr>
                                                <td style="text-align: left;border: 5px solid #0046f7;background: #018fd5;color: #fff;font-size: 1.8rem;font-weight: bold;">Supervisor Minera</td>
                                                <td style="border: 5px solid #0046f7;font-size: 1.8rem;font-weight: bold;">' . $data[0]['emplMIN']['nameempM'] . '</td>
                                            </tr>
                                            <tr>
                                                <td style="text-align: left;border: 5px solid #0046f7;background: #018fd5;color: #fff;font-size: 1.8rem;font-weight: bold;">Realizado por:</td>
                                                <td style="border: 5px solid #0046f7;font-size: 1.8rem;font-weight: bold;">' . $data[0]['user']['NameU'] . '</td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </td>
                            </tr>            
                            <tr>
                                <td colspan="3" style="border: 5px solid #0046f7;background: #018fd5;color: #fff;font-size: 2.3rem;font-weight: bold;">Objetivos de la inspección y Hallazgos.</td>
                            </tr>
                            <tr>
                                <td colspan="3" style="border: 5px solid #0046f7;font-size: 1.8rem;font-weight: bold;">Objetivo:' . $data[0]['target'] . '</td>
                            </tr>
                            <tr style="border: 5px solid #0046f7;">
                                <td colspan="3" style="font-size: 1.8rem; text-align: justify;">
                                ' . $data[0]['content'] . '
                                </td>
                            </tr>
                            <tr>
                                <td colspan="3" style="border: 5px solid #0046f7;background: #018fd5;color: #fff;font-size: 2rem;font-weight: bold;">REGISTROS FOTOGRAFICOS</td>
                            </tr>            
                            <tr>
                                <td colspan="3">
                                    <table>
                                        <tbody>
                                            ' . $imagepdf . '
                                        </tbody>
                                    </table>
                                </td>                
                            </tr>
                            <tr>
                                <td colspan="3" style="border: 5px solid #0046f7;font-size: 2rem;font-weight: bold;color: #c50c0c;">
                                    Estimación de desgaste Flash en Terreno.
                                </td>
                            </tr>';
            foreach ($RevisionesPasadas as $revisionpasada) :
                $installationDate2 = convertirfechanormal($revisionpasada['installationDate']);
                $measurementDate2 = convertirfechanormal($revisionpasada['measurementDate']);
                $projectionapi = convertirfechanormal($revisionpasada['projection']);
                $projectionapi2 = convertirfechanormal($revisionpasada['projection2']);
                $pdfcontent .= '
                    <tr>
                        <td style="text-align: justify;padding: 50px 80px 50px;font-size:23px;">
                            <div>
                                <img src="' . $revisionpasada['imagen'] . '" style="width:100%;height:450px;margin-bottom:10px;">
                            </div>
                            <div >
                            ' . $revisionpasada['description'] . '
                            </div>
                        </td>
                        <td colspan="1">
                        <table class="desgaste">
                            <tbody>
                                <tr>
                                    <td colspan="2" style="font-size: 1.5rem;">Medicion terreno</td>
                                    <td style="font-size: 1.5rem;">Fecha de Instalacion</td>
                                    <td style="font-size: 1.5rem;">' . $installationDate2 . '</td>
                                    <td style="font-size: 1.5rem;">Fecha Medición </td>
                                    <td style="font-size: 1.5rem;">' . $measurementDate2 . '</td>                                
                                </tr>
                                <tr>
                                    <td style="font-size: 1.5rem;">Pto Medición</td>
                                    <td style="font-size: 1.5rem;">Espesor Nominal</td>
                                    <td style="font-size: 1.5rem;">Espesor Remanente</td>
                                    <td style="font-size: 1.5rem;">Límite de Cambio</td>
                                    <td style="font-size: 1.5rem;">mm/dia</td>
                                    <td style="font-size: 1.5rem;">Proyección</td>
                                </tr>
                                <tr>
                                    <td style="background-color: #cec6c6;font-size: 1.5rem;">Placa</td>
                                    <td style="background-color: #71d0ff;font-size: 1.5rem;">' . $revisionpasada['nominalThickness'] . '</td>
                                    <td style="background-color: #cec6c6;font-size: 1.5rem;">' . $revisionpasada['remainingThickness'] . '</td>
                                    <td style="font-size: 1.5rem;">' . $revisionpasada['exchangeLimit'] . '</td>
                                    <td style="font-size: 1.5rem;">' . $revisionpasada['monthDay'] . '</td>
                                    <td style="background-color: #ffc1c1;color: #c50c0c;font-weight: bold;font-size: 1.5rem;">' . $projectionapi . '</td>
                                </tr>
                                <tr>
                                    <td style="background-color: #cec6c6;font-size: 1.5rem;">Lifter</td>
                                    <td style="background-color: #71d0ff;font-size: 1.5rem;">' . $revisionpasada['nominalThickness2'] . '</td>
                                    <td style="background-color: #cec6c6;font-size: 1.5rem;">' . $revisionpasada['remainingThickness2'] . '</td>
                                    <td style="font-size: 1.5rem;">' . $revisionpasada['exchangeLimit2'] . '</td>
                                    <td style="font-size: 1.5rem;">' . $revisionpasada['monthDay2'] . '</td>
                                    <td style="font-size: 1.5rem;">' . $projectionapi2 . '</td>
                                </tr>
                                <tr>
                                    <td colspan="3" style="font-size: 1.5rem;font-weight: bold;color: #000;">Proyeccion Pieza </td>
                                    <td colspan="3" style="font-size: 1.5rem;font-weight: bold;color: #c50c0c">' . $projectionapi . '</td>
                                </tr>
                            </tbody>
                        </table>
                        </td>          
                    </tr>';
            endforeach;

            $pdfcontent .= '
                    <tr>
                                <td style="text-align: justify;padding: 50px 80px 50px;font-size:23px;">
                                    <div>
                                        <img src="' . $data[0]['flash_wear']['imagen'] . '" style="width:100%;height:450px;margin-bottom:10px;">
                                    </div>
                                    <div >
                                    ' . $data[0]['flash_wear']['description'] . '
                                    </div>
                                </td>
                                <td colspan="1">
                                <table class="desgaste">
                                    <tbody>
                                        <tr>
                                            <td colspan="2" style="font-size: 1.5rem;">Medicion terreno</td>
                                            <td style="font-size: 1.5rem;">Fecha de Instalacion</td>
                                            <td style="font-size: 1.5rem;">' . $installationDate . '</td>
                                            <td style="font-size: 1.5rem;">Fecha Medición </td>
                                            <td style="font-size: 1.5rem;">' . $measurementDate . '</td>                                
                                        </tr>
                                        <tr>
                                            <td style="font-size: 1.5rem;">Pto Medición</td>
                                            <td style="font-size: 1.5rem;">Espesor Nominal</td>
                                            <td style="font-size: 1.5rem;">Espesor Remanente</td>
                                            <td style="font-size: 1.5rem;">Límite de Cambio</td>
                                            <td style="font-size: 1.5rem;">mm/dia</td>
                                            <td style="font-size: 1.5rem;">Proyección</td>
                                        </tr>
                                        <tr>
                                            <td style="background-color: #cec6c6;font-size: 1.5rem;">Placa</td>
                                            <td style="background-color: #71d0ff;font-size: 1.5rem;">' . $data[0]['flash_wear']['nominalThickness'] . '</td>
                                            <td style="background-color: #cec6c6;font-size: 1.5rem;">' . $data[0]['flash_wear']['remainingThickness'] . '</td>
                                            <td style="font-size: 1.5rem;">' . $data[0]['flash_wear']['exchangeLimit'] . '</td>
                                            <td style="font-size: 1.5rem;">' . $data[0]['flash_wear']['monthDay'] . '</td>
                                            <td style="background-color: #ffc1c1;color: #c50c0c;font-weight: bold;font-size: 1.5rem;">' . $projection . '</td>
                                        </tr>
                                        <tr>
                                            <td style="background-color: #cec6c6;font-size: 1.5rem;">Lifter</td>
                                            <td style="background-color: #71d0ff;font-size: 1.5rem;">' . $data[0]['flash_wear']['nominalThickness2'] . '</td>
                                            <td style="background-color: #cec6c6;font-size: 1.5rem;">' . $data[0]['flash_wear']['remainingThickness2'] . '</td>
                                            <td style="font-size: 1.5rem;">' . $data[0]['flash_wear']['exchangeLimit'] . '</td>
                                            <td style="font-size: 1.5rem;">' . $data[0]['flash_wear']['monthDay'] . '</td>
                                            <td style="font-size: 1.5rem;">' . $projection2 . '</td>
                                        </tr>
                                        <tr>
                                            <td colspan="3" style="font-size: 1.5rem;font-weight: bold;color: #000;">Proyeccion Pieza </td>
                                            <td colspan="3" style="font-size: 1.5rem;font-weight: bold;color: #c50c0c">' . $projection . '</td>
                                        </tr>
                                    </tbody>
                                </table>
                                </td>          
                            </tr>
                        
                            <tr>
                                <td style="text-align: justify;font-size:23px;padding: 50px 80px 50px;">
                                <img src="' . $data[0]['fill_level']['Imagenfl'] . '" style="width:100%;height:450px;margin-bottom:10px;">
                                    <div >
                                    ' . $data[0]['fill_level']['description'] . '
                                    </div>
                                </td>
                                <td colspan="3">
                                    <table class="estimacion">
                                        <tbody>
                                            <tr>
                                                <td colspan="2" style="color: #0046f7;font-size: 2.5rem;font-weight: bold;text-align: center;">Estimación, Nivel de Llenado</td>
                                            </tr>
                                            <tr>
                                                <td style="font-size: 1.8rem;">Minera</td>
                                                <td style="text-align: right;font-size: 1.8rem;">' . $data[0]['equipment']['companyId']['name'] . '</td>
                                            </tr>
                                            <tr>
                                                <td style="font-size: 1.8rem;">Fecha Inspección</td>
                                                <td style="text-align: right;font-size: 1.8rem;">' . $fechainspeccion . '</td>
                                            </tr>
                                            <tr>
                                                <td style="font-size: 1.8rem;">Diámetro [ft]</td>
                                                <td style="text-align: right;font-size: 1.8rem;">' . $data[0]['fill_level']['diameter'] . '</td>
                                            </tr>
                                            <tr>
                                                <td style="font-size: 1.8rem;">Número total de lifter</td>
                                                <td style="text-align: right;font-size: 1.8rem;">' . $data[0]['fill_level']['totalNumberLifters'] . '</td>
                                            </tr>
                                            <tr>
                                                <td style="font-size: 1.8rem;">Lifter expuestos</td>
                                                <td style="text-align: right;font-size: 1.8rem;">' . $data[0]['fill_level']['exposedLifter'] . '</td>
                                            </tr>
                                            <tr>
                                                <td style="font-size: 1.8rem;">Altura.</td>
                                                <td style="text-align: right;font-size: 1.8rem;">' . $data[0]['fill_level']['height'] . '</td>
                                            </tr>
                                            <tr>
                                                <td style="font-size: 1.8rem;">Nivel de llenado</td>
                                                <td style="text-align: right;font-size: 1.8rem;">' . $data[0]['fill_level']['fillingLevel'] . '</td>
                                            </tr>
                                            
                                        </tbody>
                                    </table>
                                </td>
                            </tr>
                            <tr>
                                <td colspan="3" style="border: 5px solid #0046f7;background: #018fd5;color: #fff;font-size: 2.3rem;font-weight: bold;">Conclusiones y Recomendaciones</td>
                            </tr>
                            <tr>
                                <td colspan="3" style="border: 5px solid #0046f7;font-size: 1.8rem;text-align:justify;">' . $data[0]['conclusions'] . '</td>
                            </tr>
                        </tbody>
                    </table>
                </body>
                ';
            $nombrePdf = uniqid() . 'QuickReport';


            $data = $this->get('db')->update(
                'technical_review',
                [
                    "pathPDF" => $nombrePdf . '.pdf',
                    'publishedPDF' => 'Si',
                ],
                [
                    'id' => $id/*para colocar el id linea 3076*/
                ]
            );

            if ($data) {
                $mpdf->WriteHTML($pdfcontent);
                $mpdf->Output('reportes/' . $nombrePdf . '.pdf', 'F');
                $data = array("Respuesta" => "parsePdf");
                $response->getBody()->write(json_encode($data));
                return $response
                    ->withHeader('Content-Type', 'application/json');
            } else {
                $data = array("Respuesta" => "noParsepdf");
                $response->getBody()->write(json_encode($data));
                return $response
                    ->withHeader('Content-Type', 'application/json');
            }
        } else {
            $data = array("Error" => "error");
            $response->getBody()->write(json_encode($data));
            return $response
                ->withHeader('Content-Type', 'application/json');
        }
    });

    //Lamar al PDF para la app
    $group->get('detailstechnicalreviewallpdfapp/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->select(
            'technical_review(tr)',
            [
                '[><]equipment(eq)' => ['tr.equipmentId' => 'id'],
                '[><]company(c)' => ['eq.companyId' => 'id'],
                '[><]company_employees(ce)' => ['tr.supervisorUserId' => 'id'],
                '[><]company_employees(cem)' => ['tr.supervisorMinId' => 'id'],
                '[>]fill_level(fl)' => ['tr.id' => 'technicalReviewId'],
                '[>]flash_wear(fw)' => ['tr.id' => 'technicalReviewId'],
                '[>]file_technical(ft)' => ['tr.id' => 'technicalReviewId'],
                '[>]user(u)' => ['tr.technicalUserId' => 'id'],
            ],
            [
                "tr.id",
                "tr.title",
                "tr.content",
                "tr.conclusions",
                "tr.status",
                "tr.isDeleted",
                "tr.inspectionDate",
                "tr.equipmentId",
                "tr.technicalUserId",
                "tr.supervisorUserId",
                "tr.target",
                "tr.pathPdf",
                "fill_level" => [
                    "fl.id(idfill_level)",
                    "fl.diameter",
                    "fl.totalNumberLifters",
                    "fl.exposedLifter",
                    "fl.height",
                    "fl.fillingLevel",
                    "fl.isDeleted(isDeletedfill_level)",
                    "fl.fillingLevel",
                    "fl.technicalReviewId(technicalReviewIdfill_level)"
                ],
                "flash_wear" => [
                    "fw.id(idflash_wear)",
                    "fw.nominalThickness",
                    "fw.remainingThickness",
                    "fw.exchangeLimit",
                    "fw.monthDay",
                    "fw.projection",
                    "fw.installationDate",
                    "fw.measurementDate",
                    "fw.isDeleted(isDeletedflash_wear)",
                    "fw.technicalReviewId(technicalReviewIdflash_wear)"
                ],
                "file_technical" => [
                    "ft.id(idfile_technical)",
                    "ft.filePath",
                    "ft.isDeleted",
                    "ft.technicalReviewId(technicalReviewIdfile_technical)"
                ],
            ],
            [
                'tr.id' => $id,
                'tr.status' => 'COMPLETADO',
                'tr.publishedPDF' => 'Si',
            ]
        );

        if ($data) {
            if ($data[0]['pathPdf'] != 0) {
                $path = 'reportes/' . $data[0]['pathPdf'];

                $fh = fopen($path, 'rb');
                $file_stream = new Stream($fh);

                return $response->withBody($file_stream)
                    ->withHeader('Content-Disposition', 'attachment; filename=' . $data[0]['pathPdf'] . ';')
                    ->withHeader('Content-Type', mime_content_type($path))
                    ->withHeader('Content-Length', filesize($path));
            } else {
                $data = array("Respuesta" => "sinPdf");
                $response->getBody()->write(json_encode($data));
                return $response
                    ->withHeader('Content-Type', 'application/json');
            }
        } else {
            $data = array("Error" => "no existe");
            $response->getBody()->write(json_encode($data));
            return $response
                ->withHeader('Content-Type', 'application/json');
        }
    });

    $group->get('existencia/pdf/{id}', function ($request, $response, array $args) {
        $id = $args['id'];
        $data = $this->get('db')->select('technical_review', 'pathPDF', ['id' => $id]);
        if (!$data) {
            $data = array("Respuesta" => "No se encontro");
        }
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    /*endpoint para la app */
    $group->get('detailstechnicalreview/company/{idcompany}', function ($request, $response, array $args) {
        $id = $args['idcompany'];
        $data = $this->get('db')->select(
            'technical_review(tr)',
            [
                '[><]equipment(eq)' => ['tr.equipmentId' => 'id'],
                '[><]company(c)' => ['eq.companyId' => 'id']
            ],
            [
                "tr.id",
                "tr.title",
                "tr.content",
                "tr.conclusions",
                "tr.status",
                "tr.inspectionDate",
                "tr.target",
                "tr.equipmentId",
                "tr.technicalUserId",
                "tr.supervisorUserId"
            ],
            [
                'c.id' => $id,
                'tr.status' => 'COMPLETADO',
                'tr.publishedPDF' => 'Si',
            ]

        );
        $response->getBody()->write(json_encode($data));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
    /*endpoit cambio de contraseña para la app*/
    $group->put('updatepassword', function ($request, $response, array $args) {
        $datos = $request->getParsedBody();
        $id = $datos['id'];
        $oldpassword = $datos['oldpassword'];
        $oldencryp = Encriptacion::encryption($oldpassword);
        $newpassword = $datos['newpassword'];
        $newencryp = Encriptacion::encryption($newpassword);
        $repeatnewpassword = $datos['repeatnewpassword'];

        $data = $this->get('db')->get(
            'user(u)',
            "password",
            ["AND" => [
                "u.password" => $oldencryp,
                "u.id" => $id
            ]]
        );

        if ($data) {
            if ($newpassword != "") {
                if ($newpassword == $repeatnewpassword) {
                    $newData = $this->get('db')->update(
                        'user',
                        [
                            "password" => $newencryp,
                        ],
                        [
                            'id' => $id
                        ]
                    );
                    if ($newData) {
                        $newData = array("respuesta" => "password actualizado");
                    } else {
                        $newData = array("respuesta" => "error");
                    }
                } else {
                    $newData = array("respuesta" => "password no coinciden");
                }
            } else {
                $newData = array("respuesta" => "newpassword no vacio");
            }
        } else {
            $newData = array("respuesta" => "no existe el oldpassword");
        }

        $response->getBody()->write(json_encode($newData));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });
})->add(new \Tuupola\Middleware\JwtAuthentication([
    "path" => ["/api/"],
    //"secure" => true,
    //"relaxed" => ["localhost","serviciotega.gsystemperu.com" ],
    "secret" => getenv('JWT_KEY'),
    "algorithm" => ['HS512'],
    "error" => function ($response, $arguments) {
        $data["status"] = "error";
        $data["message"] = $arguments["message"];
        return $response
            ->withHeader("Content-Type", "application/json")
            ->getBody()->write(json_encode(
                $data,
                JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT
            ));
    }
]));


$app->run();

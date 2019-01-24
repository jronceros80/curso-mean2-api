'use strict'

var jwt = require('jwt-simple');
var moment = require('moment');
var secret = 'clave_secreta_del_curso';

exports.ensureAuth = function(req, res, next){
    if(!req.headers.authorization){
        return res.status(403).send({message: 
            'la peticion no tiene cabecera de authenticacion'
        });
    }

    // Recuperamos el token sustituyendo las comillas simples y dobles que vienen en el inicio y fin del token
    // por un espacio en blanco
    var token = req.headers.authorization.replace(/['"]+/g, '');

    try {
        var payload = jwt.decode(token, secret);

        // Verificamos que el token no este caducado
        if(payload.exp <= moment().unix()){
            return res.status(404).send({message: 
                'el token ha expirado'
            });
        }
    } catch (error) {
        return res.status(404).send({message: 
            'el token no es valido'
        });
    }

    // Añadimos a la request todos los datos del usuario
    req.user = payload;

    // Esto es para salir del middleware
    next();
};
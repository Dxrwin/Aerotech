package com.Aerotech.demo.controllers

import com.Aerotech.demo.dto.requests.*
import com.Aerotech.demo.dto.responses.*
import com.Aerotech.demo.entities.RolUsuario
import com.Aerotech.demo.services.*
import com.Aerotech.demo.security.*
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/autenticacion")
@Tag(name = "Autenticación", description = "Endpoints para autenticación y registro de usuarios")
class ControladorAutenticacion(
    private val servicioUsuario: ServicioUsuario,
    private val jwtUtil: JwtUtil
) {

    @PostMapping("/registrar")
    @Operation(summary = "Registrar nuevo usuario")
    fun registrar(@Valid @RequestBody request: CrearUsuarioRequest): ResponseEntity<RespuestaApi<UsuarioResponse>> {
        val usuario = servicioUsuario.crearUsuario(request)
        return ResponseEntity.status(HttpStatus.CREATED)
            .body(RespuestaApi.exitoso(usuario, "Usuario creado exitosamente"))
    }

    @PostMapping("/iniciar-sesion")
    @Operation(summary = "Iniciar sesión")
    fun iniciarSesion(@Valid @RequestBody request: IniciarSesionRequest): ResponseEntity<RespuestaApi<Map<String, Any>>> {
        val usuario = servicioUsuario.autenticarUsuario(request)
        val token = jwtUtil.generarToken(usuario.correo)
        println("Token generado: $token") // Para propósitos de depuración
        val response = mapOf(
            "usuario" to usuario,
            "token" to token
        )
        return ResponseEntity.ok(RespuestaApi.exitoso(response, "Inicio de sesión exitoso"))
    }


    @PostMapping("/obtener-token")
    @Operation(summary = "Obtener token para roles específicos ( ADMINISTRADOR, EMPLEADO )")
    fun obtenerToken(@Valid @RequestBody request: IniciarSesionRequest): ResponseEntity<RespuestaApi<Map<String, Any>>> {
        val usuario = servicioUsuario.autenticarUsuario(request)
        println("usaurio desde el servicio: $usuario") // Para propósitos de depuración

        // Verificar si el rol es ADMINISTRADOR o EMPLEADO
        if (usuario.rol != RolUsuario.ADMINISTRADOR && usuario.rol != RolUsuario.EMPLEADO) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(RespuestaApi.error("Acceso denegado: Rol no autorizado"))
        }

        val token = jwtUtil.generarToken(usuario.correo)
        println("Token generado: $token") // Para propósitos de depuración
        val response = mapOf(
            "usuario" to usuario,
            "token" to token
        )
        println("response: $response") // Para propósitos de depuración
        return ResponseEntity.ok(RespuestaApi.exitoso(response, "Token generado exitosamente"))
    }


    @PostMapping("/obtener-token-cliente")
    @Operation(summary = "Obtener token solo para clientes")
    fun obtenerTokenCliente(@Valid @RequestBody request: IniciarSesionRequest): ResponseEntity<RespuestaApi<Map<String, Any>>> {
        val usuario = servicioUsuario.autenticarUsuario(request)

        // Verificar si el rol es "CLIENTE"
        if (usuario.rol != RolUsuario.CLIENTE) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(RespuestaApi.error("Acceso denegado: Solo los clientes pueden obtener un token"))
        }

        val token = jwtUtil.generarToken(usuario.correo)
        val response = mapOf(
            "usuario" to usuario,
            "token" to token
        )
        return ResponseEntity.ok(RespuestaApi.exitoso(response, "Token generado exitosamente para cliente"))
    }



}
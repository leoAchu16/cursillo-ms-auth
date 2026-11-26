package org.cursillo.auth.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.cursillo.auth.service.UsuarioService;
import org.cursillo.commons.dto.CambioContrasenhaRequestDTO;
import org.cursillo.commons.dto.PerfilRequestDTO;
import org.cursillo.commons.dto.Rol;
import org.cursillo.commons.dto.UsuarioRequestDTO;
import org.cursillo.commons.dto.UsuarioResponseDTO;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/usuarios")
@RequiredArgsConstructor
public class UsuarioController {

    private final UsuarioService service;

    @PreAuthorize("hasRole('SECRETARIA')")
    @PostMapping
    public ResponseEntity<UsuarioResponseDTO> create(@RequestBody @Valid UsuarioRequestDTO dto) {
        log.info("POST /usuarios - creando usuario");
        return ResponseEntity.status(HttpStatus.CREATED).body(service.crearProfesor(dto));
    }

    // ----------PERFIL DEL USUARIO LOGUEADO (cualquier rol)----------

    @GetMapping("/me")
    public ResponseEntity<UsuarioResponseDTO> getPerfil() {
        log.info("GET /usuarios/me - obteniendo perfil");
        return ResponseEntity.ok(service.obtenerPerfil());
    }

    @PutMapping("/me")
    public ResponseEntity<UsuarioResponseDTO> updatePerfil(@RequestBody @Valid PerfilRequestDTO dto) {
        log.info("PUT /usuarios/me - actualizando perfil");
        return ResponseEntity.ok(service.actualizarPerfil(dto));
    }

    @PutMapping("/me/contrasenha")
    public ResponseEntity<Void> updateContrasenha(@RequestBody @Valid CambioContrasenhaRequestDTO dto) {
        log.info("PUT /usuarios/me/contrasenha - cambiando contraseña");
        service.cambiarContrasenha(dto);
        return ResponseEntity.noContent().build();
    }

    // ----------GESTIÓN DE USUARIOS (secretaría)----------

    // Solo secretaría: cada usuario edita lo suyo por /usuarios/me
    @PreAuthorize("hasRole('SECRETARIA')")
    @PutMapping("/{id}")
    public ResponseEntity<UsuarioResponseDTO> update(@PathVariable("id") Integer idUsuario, @RequestBody @Valid UsuarioRequestDTO dto) {
        log.info("PUT /usuarios/{} - actualizando usuario", idUsuario);
        return ResponseEntity.ok(service.actualizar(idUsuario, dto));
    }
    @PreAuthorize("hasAnyRole('SECRETARIA', 'PROFESOR', 'ALUMNO')")
    @GetMapping("/{id}")
    public ResponseEntity<UsuarioResponseDTO> getById(@PathVariable("id") Integer idUsuario) {
        log.info("GET /usuarios/{} - obteniendo usuario", idUsuario);
        return ResponseEntity.ok(service.obtenerPorId(idUsuario));
    }

    @PreAuthorize("hasAnyRole('SECRETARIA', 'PROFESOR', 'ALUMNO')")
    @GetMapping
    public ResponseEntity<Page<UsuarioResponseDTO>> getAll(@RequestParam(value = "rol", required = false) Rol rol,
                                                           @RequestParam(value = "nombre", required = false) String nombre,
                                                           @ParameterObject Pageable pageable) {
        log.info("GET /usuarios - listando usuarios (pagina: {}, tamanho: {})",
                pageable.getPageNumber(), pageable.getPageSize());
        return ResponseEntity.ok(service.listarUsuarios(rol, nombre, pageable));
    }

    @PreAuthorize("hasRole('SECRETARIA')")
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable("id") Integer idUsuario) {
        log.info("DELETE /usuarios/{} - eliminando usuario", idUsuario);
        service.eliminar(idUsuario);
        return ResponseEntity.noContent().build();
    }

    @PreAuthorize("hasRole('SECRETARIA')")
    @PostMapping("/{id}/roles/{rol}")
    public ResponseEntity<UsuarioResponseDTO> addRol(@PathVariable("id") Integer idUsuario,
                                                     @PathVariable("rol") Rol rol) {
        log.info("POST /usuarios/{}/roles/{} - agregando rol", idUsuario, rol);
        return ResponseEntity.ok(service.agregarRol(idUsuario, rol));
    }

    @PreAuthorize("hasRole('SECRETARIA')")
    @DeleteMapping("/{id}/roles/{rol}")
    public ResponseEntity<UsuarioResponseDTO> removeRol(@PathVariable("id") Integer idUsuario,
                                                        @PathVariable("rol") Rol rol) {
        log.info("DELETE /usuarios/{}/roles/{} - quitando rol", idUsuario, rol);
        return ResponseEntity.ok(service.quitarRol(idUsuario, rol));
    }
}
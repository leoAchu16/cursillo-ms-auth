package org.cursillo.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.cursillo.auth.exception.BadRequestException;
import org.cursillo.auth.exception.BusinessException;
import org.cursillo.auth.exception.NotFoundException;
import org.cursillo.auth.mapper.UsuarioMapper;
import org.cursillo.auth.repository.UsuarioRepository;
import org.cursillo.commons.dto.RegistroRequestDTO;
import org.cursillo.commons.dto.UsuarioRequestDTO;
import org.cursillo.commons.dto.UsuarioResponseDTO;
import org.cursillo.commons.entities.Enums.Rol;
import org.cursillo.commons.entities.Usuarios.Usuario;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class UsuarioService {

    private static final int LARGO_MINIMO_CONTRASENHA = 8;

    private final UsuarioRepository usuarioRepo;
    private final UsuarioMapper usuarioMapper;
    private final PasswordEncoder passwordEncoder;


    @Transactional
    public UsuarioResponseDTO registrarAlumno(RegistroRequestDTO registro) {
        log.debug("Registro de alumno con email {}", registro.getEmail());
        UsuarioRequestDTO dto = new UsuarioRequestDTO()
                .nombre(registro.getNombre())
                .email(registro.getEmail())
                .contrasenha(registro.getContrasenha())
                .telefono(registro.getTelefono())
                .rol(org.cursillo.commons.dto.Rol.ALUMNO);

        return guardar(dto);
    }

    @Transactional
    public UsuarioResponseDTO crearProfesor(UsuarioRequestDTO dto) {
        log.debug("Registro de profesor con email {}", dto.getEmail());
        if (dto.getRol() != org.cursillo.commons.dto.Rol.PROFESOR)
            throw new BadRequestException("El rol del usuario a crear debe ser PROFESOR.");
        return guardar(dto);
    }

    @Transactional
    public UsuarioResponseDTO actualizar(Integer id, UsuarioRequestDTO dto) {
        log.debug("Actualizando usuario con id {}", id);
        validarDatos(dto, false);

        Usuario existente = usuarioRepo.findByIdUsuarioAndActivoTrue(id)
                .orElseThrow(() -> new NotFoundException("Usuario no encontrado. Id: " + id));

        // entidad temporal, solo para convertir los roles del DTO al enum de la entidad
        Usuario temporal = usuarioMapper.toEntity(dto);
        temporal.getRolesAdicionales().forEach(this::validarRolAsignable);
        if (temporal.getRol() != existente.getRol())
            throw new BadRequestException("No se puede cambiar el rol principal de un usuario.");

        String email = normalizar(dto.getEmail());
        if (!email.equals(existente.getEmail()) && usuarioRepo.existsByEmail(email))
            throw new BusinessException("Ya existe un usuario con ese email.");

        existente.setNombre(dto.getNombre());
        existente.setTelefono(dto.getTelefono());
        existente.setEmail(email);
        if (dto.getContrasenha() != null && !dto.getContrasenha().isBlank())
            existente.setContrasenha(passwordEncoder.encode(dto.getContrasenha()));

        existente.getRolesAdicionales().clear();
        existente.getRolesAdicionales()
                .addAll(adicionalesSinRepetir(existente, temporal.getRolesAdicionales()));

        return usuarioMapper.toDto(usuarioRepo.save(existente));
    }

    /**
     * Obtiene un usuario activo por su id.
     * @param id id del usuario
     * @return DTO del usuario
     */
    @Transactional(readOnly = true)
    public UsuarioResponseDTO obtenerPorId(Integer id) {
        log.debug("Buscando usuario con id {}", id);
        return usuarioMapper.toDto(usuarioRepo.findByIdUsuarioAndActivoTrue(id)
                .orElseThrow(() -> new NotFoundException("Usuario no encontrado. Id: " + id)));
    }


    /**
     * Obtiene una lista de usuarios activos con paginación.
     * @param pageable información de paginación
     * @return Page con los usuarios activos
     */
    @Transactional(readOnly = true)
    public Page<UsuarioResponseDTO> listar(Pageable pageable) {
        log.debug("Listando usuarios activos con paginacion");
        return usuarioRepo.findAllByActivoTrue(pageable).map(usuarioMapper::toDto);
    }


    /**
     * Eliminación lógica de un usuario. Se marca como inactivo.
     * @param id id del usuario a eliminar
     */
    @Transactional
    public void eliminar(Integer id) {
        log.debug("Eliminacion logica del usuario con id {}", id);
        Usuario existente = usuarioRepo.findByIdUsuarioAndActivoTrue(id)
                .orElseThrow(() -> new NotFoundException("Usuario no encontrado. Id: " + id));
        existente.setActivo(false);
        usuarioRepo.save(existente);
    }

    /**
     * Agrega un rol adicional a un usuario.
     * @param id id del usuario
     * @param rolDto rol a agregar
     * @return DTO del usuario actualizado
     */
    @Transactional
    public UsuarioResponseDTO agregarRol(Integer id, org.cursillo.commons.dto.Rol rolDto) {
        log.debug("Agregando rol {} al usuario con id {}", rolDto, id);
        Rol rol = Rol.valueOf(rolDto.name());
        validarRolAsignable(rol);

        Usuario usuario = usuarioRepo.findByIdUsuarioAndActivoTrue(id)
                .orElseThrow(() -> new NotFoundException("Usuario no encontrado. Id: " + id));

        if (usuario.getRol() == rol)
            throw new BusinessException("Ese ya es el rol principal del usuario.");
        if (!usuario.getRolesAdicionales().add(rol))
            throw new BusinessException("El usuario ya tiene ese rol.");

        return usuarioMapper.toDto(usuarioRepo.save(usuario));
    }

    /**
     * Quita un rol adicional a un usuario. No se puede quitar el rol principal.
     * @param id id del usuario
     * @param rolDto rol a quitar
     * @return DTO del usuario actualizado
     */
    @Transactional
    public UsuarioResponseDTO quitarRol(Integer id, org.cursillo.commons.dto.Rol rolDto) {
        log.debug("Quitando rol {} al usuario con id {}", rolDto, id);
        Rol rol = Rol.valueOf(rolDto.name());

        Usuario usuario = usuarioRepo.findByIdUsuarioAndActivoTrue(id)
                .orElseThrow(() -> new NotFoundException("Usuario no encontrado. Id: " + id));

        if (usuario.getRol() == rol)
            throw new BadRequestException("No se puede quitar el rol principal de un usuario.");
        if (!usuario.getRolesAdicionales().remove(rol))
            throw new NotFoundException("El usuario no tiene ese rol adicional.");

        return usuarioMapper.toDto(usuarioRepo.save(usuario));
    }

    // ----------FUNCIONES AUXILIARES----------


    /**
     * Valida que el rol del usuario sea asignable mediante la API.
     * @param rol rol a validar
     */
    private void validarRolAsignable(Rol rol) {
        if (rol == Rol.SECRETARIA)
            throw new BadRequestException("No se puede asignar este rol.");
    }

    /**
     * Guarda un nuevo usuario en la base de datos.
     * @param dto DTO con los datos del usuario
     * @return DTO del usuario guardado
     */
    private UsuarioResponseDTO guardar(UsuarioRequestDTO dto) {
        validarDatos(dto, true);

        String email = normalizar(dto.getEmail());
        if(usuarioRepo.existsByEmail(email)) throw new BusinessException("Ya existe un usuario con ese email.");

        Usuario usuario = usuarioMapper.toEntity(dto);
        usuario.getRolesAdicionales().forEach(this::validarRolAsignable);
        usuario.setEmail(email);
        usuario.setContrasenha(passwordEncoder.encode(dto.getContrasenha()));
        usuario.setRolesAdicionales(adicionalesSinRepetir(usuario, usuario.getRolesAdicionales()));

        return usuarioMapper.toDto(usuarioRepo.save(usuario));
    }

    /**
     * Valida los datos del DTO de usuario.
     * @param dto DTO de usuario
     * @param contrasenhaObligatoria indica si la contraseña es obligatoria
     */
    private void validarDatos(UsuarioRequestDTO dto, boolean contrasenhaObligatoria) {
        if (dto.getNombre() == null || dto.getNombre().isBlank())
            throw new BadRequestException("El nombre es obligatorio.");
        if (dto.getEmail() == null || !dto.getEmail().trim().matches("^[^@\\s]+@[^@\\s]+$"))
            throw new BadRequestException("El email es obligatorio y debe tener un formato válido.");
        if (dto.getRol() == null)
            throw new BadRequestException("El rol es obligatorio.");

        boolean hayContrasenha = dto.getContrasenha() != null && !dto.getContrasenha().isBlank();
        if (contrasenhaObligatoria && !hayContrasenha)
            throw new BadRequestException("La contraseña es obligatoria.");
        if (hayContrasenha && dto.getContrasenha().length() < LARGO_MINIMO_CONTRASENHA)
            throw new BadRequestException(
                    "La contraseña debe tener al menos " + LARGO_MINIMO_CONTRASENHA + " caracteres.");
    }


    /**
     * Normaliza un email eliminando espacios y convirtiéndolo a minúsculas.
     * @param email email a normalizar
     * @return email normalizado
     */
    private String normalizar(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * Elimina el rol principal del usuario de la lista de roles adicionales, si está presente.
     * @param usuario usuario
     * @param adicionales roles adicionales
     * @return roles adicionales sin el rol principal del usuario
     */
    private Set<Rol> adicionalesSinRepetir(Usuario usuario, Set<Rol> adicionales) {
        Set<Rol> limpios = new HashSet<>();
        if (adicionales != null) limpios.addAll(adicionales);
        limpios.remove(usuario.getRol());
        return limpios;
    }
}
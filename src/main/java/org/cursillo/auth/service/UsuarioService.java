package org.cursillo.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.cursillo.auth.exception.AccessDeniedException;
import org.cursillo.auth.exception.BadRequestException;
import org.cursillo.auth.security.UsuarioActual;
import org.cursillo.auth.exception.BusinessException;
import org.cursillo.auth.exception.NotFoundException;
import org.cursillo.auth.mapper.UsuarioMapper;
import org.cursillo.auth.repository.UsuarioRepository;
import org.cursillo.commons.dto.CambioContrasenhaRequestDTO;
import org.cursillo.commons.dto.PerfilRequestDTO;
import org.cursillo.commons.dto.RegistroRequestDTO;
import org.cursillo.commons.dto.UsuarioRequestDTO;
import org.cursillo.commons.dto.UsuarioResponseDTO;
import org.cursillo.commons.entities.Enums.Rol;
import org.cursillo.commons.entities.Usuarios.Alumno;
import org.cursillo.commons.entities.Usuarios.Profesor;
import org.cursillo.commons.entities.Usuarios.Secretaria;
import org.cursillo.commons.entities.Usuarios.Usuario;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class UsuarioService {

    private static final int LARGO_MINIMO_CONTRASENHA = 8;
    private static final int BYTES_MAXIMOS_CONTRASENHA = 72; // límite de BCrypt

    // Largos de las columnas de la tabla usuarios
    private static final int LARGO_MAXIMO_NOMBRE = 100;
    private static final int LARGO_MAXIMO_EMAIL = 255;
    private static final int LARGO_MAXIMO_TELEFONO = 20;

    private final UsuarioRepository usuarioRepo;
    private final UsuarioMapper usuarioMapper;
    private final PasswordEncoder passwordEncoder;
    private final UsuarioActual usuarioActual;


    @Transactional
    public UsuarioResponseDTO registrarAlumno(RegistroRequestDTO registro) {
        log.debug("Registro de alumno con email {}", registro.getEmail());
        String telefono = limpiar(registro.getTelefono());
        if (telefono == null || !telefono.matches("^\\+?\\d+$"))
            throw new BadRequestException("El teléfono es obligatorio y solo puede tener números.");

        UsuarioRequestDTO dto = new UsuarioRequestDTO()
                .nombre(limpiar(registro.getNombre()))
                .email(registro.getEmail())
                .contrasenha(registro.getContrasenha())
                .telefono(telefono)
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

        // Solo la secretaria edita a cualquiera; el resto únicamente a sí mismo
        boolean esSecretaria = usuarioActual.esSecretaria();
        if (!esSecretaria && !usuarioActual.esElMismo(id))
            throw new AccessDeniedException("Solo podés editar tus propios datos.");

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

        // Los roles adicionales solo los cambia la secretaria. Si no, un alumno podría
        // editarse a sí mismo y agregarse el rol PROFESOR: se ignoran los del body.
        if (esSecretaria) {
            Set<Rol> adicionales = adicionalesSinRepetir(existente, temporal.getRolesAdicionales());
            validarCombinable(existente.getRol(), adicionales);
            existente.getRolesAdicionales().clear();
            existente.getRolesAdicionales().addAll(adicionales);
        }

        return usuarioMapper.toDto(usuarioRepo.save(existente));
    }

    // ----------PERFIL DEL USUARIO LOGUEADO----------

    /**
     * Datos del usuario logueado (GET /usuarios/me).
     */
    @Transactional(readOnly = true)
    public UsuarioResponseDTO obtenerPerfil() {
        return usuarioMapper.toDto(usuarioLogueado());
    }

    /**
     * El usuario logueado edita su nombre y su teléfono. El email, el rol y la
     * contraseña no se tocan acá (la contraseña tiene su propio endpoint).
     */
    @Transactional
    public UsuarioResponseDTO actualizarPerfil(PerfilRequestDTO dto) {
        Usuario usuario = usuarioLogueado();
        log.debug("Usuario {} actualizando su perfil", usuario.getIdUsuario());

        String nombre = limpiar(dto.getNombre());
        String telefono = limpiar(dto.getTelefono());
        if (nombre == null || nombre.isBlank())
            throw new BadRequestException("El nombre es obligatorio.");
        if (telefono == null || !telefono.matches("^\\+?\\d+$"))
            throw new BadRequestException("El teléfono es obligatorio y solo puede tener números.");
        validarLargo("nombre", nombre, LARGO_MAXIMO_NOMBRE);
        validarLargo("teléfono", telefono, LARGO_MAXIMO_TELEFONO);

        usuario.setNombre(nombre);
        usuario.setTelefono(telefono);
        return usuarioMapper.toDto(usuarioRepo.save(usuario));
    }

    /**
     * El usuario logueado cambia su contraseña. Exige la actual, para que una sesión
     * abierta o un token robado no alcancen para quedarse con la cuenta.
     */
    @Transactional
    public void cambiarContrasenha(CambioContrasenhaRequestDTO dto) {
        Usuario usuario = usuarioLogueado();
        log.debug("Usuario {} cambiando su contraseña", usuario.getIdUsuario());

        String actual = dto.getContrasenhaActual();
        String nueva = dto.getContrasenhaNueva();
        if (actual == null || actual.isBlank())
            throw new BadRequestException("La contraseña actual es obligatoria.");
        if (nueva == null || nueva.isBlank())
            throw new BadRequestException("La contraseña nueva es obligatoria.");
        // 400 y no 401: es un dato mal cargado, la sesión sigue siendo válida
        if (!passwordEncoder.matches(actual, usuario.getContrasenha()))
            throw new BadRequestException("La contraseña actual no es correcta.");
        validarContrasenha(nueva);
        if (nueva.equals(actual))
            throw new BadRequestException("La contraseña nueva tiene que ser distinta de la actual.");

        usuario.setContrasenha(passwordEncoder.encode(nueva));
        usuarioRepo.save(usuario);
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
     * Obtiene una lista de usuarios activos con paginación, opcionalmente filtrada por rol y nombre.
     *
     * @param rolDto rol para filtrar (opcional, usando la ruta completa del DTO)
     * @param nombre texto a buscar dentro del nombre (opcional, sin distinguir mayúsculas)
     * @param pageable información de paginación
     * @return Page con los usuarios activos
     */
    @Transactional(readOnly = true)
    public Page<UsuarioResponseDTO> listarUsuarios(org.cursillo.commons.dto.Rol rolDto, String nombre, Pageable pageable) {
        boolean filtrarPorNombre = nombre != null && !nombre.isBlank();
        log.debug("Listando usuarios activos con paginacion. Filtro rol: {}, nombre: {}", rolDto, nombre);

        if (rolDto != null) {
            Class<? extends Usuario> tipo = switch (rolDto) {
                case ALUMNO -> Alumno.class;
                case PROFESOR -> Profesor.class;
                case SECRETARIA -> Secretaria.class;
            };

            if (filtrarPorNombre) {
                return usuarioRepo.findByNombreContainingIgnoreCaseAndActivoTrueAndTipo(nombre.trim(), tipo, pageable)
                        .map(usuarioMapper::toDto);
            }
            return usuarioRepo.findAllByActivoTrueAndTipo(tipo, pageable)
                    .map(usuarioMapper::toDto);
        }

        if (filtrarPorNombre) {
            return usuarioRepo.findByNombreContainingIgnoreCaseAndActivoTrue(nombre.trim(), pageable)
                    .map(usuarioMapper::toDto);
        }
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
        validarCombinable(usuario.getRol(), Set.of(rol));
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
     * La única combinación de roles es profesor + alumno: la secretaría no suma otros roles.
     */
    private void validarCombinable(Rol principal, Set<Rol> adicionales) {
        if (principal == Rol.SECRETARIA && !adicionales.isEmpty())
            throw new BadRequestException("Una secretaria no puede tener otros roles.");
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

        validarLargo("nombre", dto.getNombre(), LARGO_MAXIMO_NOMBRE);
        validarLargo("email", dto.getEmail().trim(), LARGO_MAXIMO_EMAIL);
        validarLargo("teléfono", dto.getTelefono(), LARGO_MAXIMO_TELEFONO);

        boolean hayContrasenha = dto.getContrasenha() != null && !dto.getContrasenha().isBlank();
        if (contrasenhaObligatoria && !hayContrasenha)
            throw new BadRequestException("La contraseña es obligatoria.");
        if (hayContrasenha) validarContrasenha(dto.getContrasenha());
    }

    /**
     * Valida el largo de una contraseña: mínimo de caracteres y máximo de bytes que admite BCrypt.
     */
    private void validarContrasenha(String contrasenha) {
        if (contrasenha.length() < LARGO_MINIMO_CONTRASENHA)
            throw new BadRequestException(
                    "La contraseña debe tener al menos " + LARGO_MINIMO_CONTRASENHA + " caracteres.");
        if (contrasenha.getBytes(StandardCharsets.UTF_8).length > BYTES_MAXIMOS_CONTRASENHA)
            throw new BadRequestException("La contraseña es demasiado larga.");
    }

    /**
     * Usuario activo que hizo la petición, según el id del token.
     */
    private Usuario usuarioLogueado() {
        Integer id = usuarioActual.id();
        if (id == null) throw new AccessDeniedException("No hay un usuario autenticado.");
        return usuarioRepo.findByIdUsuarioAndActivoTrue(id)
                .orElseThrow(() -> new NotFoundException("Usuario no encontrado. Id: " + id));
    }

    /**
     * Valida que un dato entre en su columna de la base de datos.
     */
    private void validarLargo(String campo, String valor, int maximo) {
        if (valor != null && valor.length() > maximo)
            throw new BadRequestException("El " + campo + " no puede tener más de " + maximo + " caracteres.");
    }

    private String limpiar(String texto) {
        return texto == null ? null : texto.trim();
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
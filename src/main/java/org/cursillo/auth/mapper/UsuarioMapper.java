package org.cursillo.auth.mapper;

import org.cursillo.commons.dto.UsuarioRequestDTO;
import org.cursillo.commons.dto.UsuarioResponseDTO;
import org.cursillo.commons.entities.Usuarios.Alumno;
import org.cursillo.commons.entities.Usuarios.Profesor;
import org.cursillo.commons.entities.Usuarios.Secretaria;
import org.cursillo.commons.entities.Usuarios.Usuario;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ObjectFactory;

@Mapper(componentModel = "spring")
public interface UsuarioMapper {

    @ObjectFactory
    default Usuario crearUsuario(UsuarioRequestDTO dto) {
        if (dto.getRol() == null) throw new IllegalArgumentException("El rol es obligatorio.");

        return switch (dto.getRol()) {
            case ALUMNO -> new Alumno();
            case PROFESOR -> new Profesor();
            case SECRETARIA -> new Secretaria();
        };
    }

    @Mapping(target = "idUsuario", ignore = true)
    @Mapping(target = "contrasenha", ignore = true)
    Usuario toEntity(UsuarioRequestDTO dto);

    UsuarioResponseDTO toDto(Usuario usuario);
}

package org.cursillo.auth.repository;

import org.cursillo.commons.entities.Usuarios.Usuario;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UsuarioRepository extends JpaRepository<Usuario,Integer> {

    Optional<Usuario> findByEmailAndActivoTrue(String email);

    boolean existsByEmail(String email);

    Optional<Usuario> findByIdUsuarioAndActivoTrue(Integer id);

    Page<Usuario> findAllByActivoTrue(Pageable pageable);

    // esto busca usuarios activos por nombre con paginacion
    Page<Usuario> findByNombreContainingIgnoreCaseAndActivoTrue(String nombre, Pageable pageable);

    @Query("""
            SELECT u
            FROM Usuario u
            WHERE u.activo = true
              AND TYPE(u) = :tipo
            """)
    Page<Usuario> findAllByActivoTrueAndTipo(
            @Param("tipo") Class<? extends Usuario> tipo,
            Pageable pageable);

    // esto busca usuarios activos de un tipo (rol) por nombre con paginacion.
    // Se usa @Query porque TYPE(u) no se puede expresar con un método derivado.
    @Query("""
            SELECT u
            FROM Usuario u
            WHERE u.activo = true
              AND TYPE(u) = :tipo
              AND LOWER(u.nombre) LIKE LOWER(CONCAT('%', :nombre, '%'))
            """)
    Page<Usuario> findByNombreContainingIgnoreCaseAndActivoTrueAndTipo(
            @Param("nombre") String nombre,
            @Param("tipo") Class<? extends Usuario> tipo,
            Pageable pageable);
}

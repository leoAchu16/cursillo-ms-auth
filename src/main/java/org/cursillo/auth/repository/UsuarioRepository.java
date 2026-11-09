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

    @Query("""
            SELECT u
            FROM Usuario u
            WHERE u.activo = true
              AND TYPE(u) = :tipo
            """)
    Page<Usuario> findAllByActivoTrueAndTipo(
            @Param("tipo") Class<? extends Usuario> tipo,
            Pageable pageable);
}

package org.cursillo.auth.repository;

import org.cursillo.commons.entities.Usuarios.Usuario;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UsuarioRepository extends JpaRepository<Usuario,Integer> {

    Optional<Usuario> findByEmailAndActivoTrue(String email);

    boolean existsByEmail(String email);

    Optional<Usuario> findByIdUsuarioAndActivoTrue(Integer id);

    Page<Usuario> findAllByActivoTrue(Pageable pageable);
}

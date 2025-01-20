package cz.solutia.acme.core.repository;

import cz.solutia.acme.core.model.GeneralSettings;
import org.springframework.data.jpa.repository.JpaRepository;

public interface GeneralSettingsRepository extends JpaRepository<GeneralSettings, Integer> {
}

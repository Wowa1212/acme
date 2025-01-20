package cz.solutia.acme;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import static org.junit.jupiter.api.Assertions.assertNotNull;

@Import(MyTestContainersConfiguration.class)
@SpringBootTest
class AcmeApplicationTests {
	@Test
	void contextLoads() {
		AcmeApplication application = new AcmeApplication(null);
		assertNotNull(application, "The application context should not be null");
	}
}

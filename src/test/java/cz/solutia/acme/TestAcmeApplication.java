package cz.solutia.acme;

import org.springframework.boot.SpringApplication;

public class TestAcmeApplication {
	public static void main(String[] args) {
		SpringApplication.from(AcmeApplication::main).with(MyTestContainersConfiguration.class).run(args);
	}
}

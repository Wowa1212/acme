INSERT INTO public."user" (id, email, firstname, lastname, password, username)
    VALUES (1, 'john.doe@acme.com', 'John', 'Doe', '$2a$10$X0.dFEj6QBhbx8eo4KAd8eqwpMO32sNsL3weUmVNaTg5iSMh5ITKi', 'john.doe@acme.com')
    ON CONFLICT (id) DO NOTHING;


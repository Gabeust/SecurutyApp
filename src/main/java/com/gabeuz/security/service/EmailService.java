package com.gabeuz.security.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

/**
 * Servicio para el envío de correos electrónicos.
 *
 * Utiliza {@link JavaMailSender} para enviar mensajes MIME (HTML o texto plano).
 */
@Service
public class EmailService {
    private final JavaMailSender mailSender;

    private final String fromEmail;
    /**
     * Constructor para inyectar el JavaMailSender.
     *
     * @param mailSender componente de envío de correos configurado en Spring
     */
    public EmailService(JavaMailSender mailSender,  @Value("${spring.mail.username}") String fromEmail) {
        this.mailSender = mailSender;
        this.fromEmail = fromEmail;
    }
    /**
     * Envía un correo electrónico al destinatario especificado.
     *
     * @param to      dirección de correo electrónico del destinatario
     * @param subject asunto del correo
     * @param content contenido del mensaje (puede ser HTML)
     * @throws EmailSendingException si ocurre un error durante el envío
     */
    public void sendEmail(String to, String subject, String content){
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper= new MimeMessageHelper(mimeMessage, true);
            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(content, true);
            mailSender.send(mimeMessage);
        } catch (MessagingException e) {

            throw new EmailSendingException("Error sending email to", e);
        }
    }
    /**
     * Excepción personalizada para errores al enviar correos.
     */
    public static class EmailSendingException extends RuntimeException {
        public EmailSendingException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}


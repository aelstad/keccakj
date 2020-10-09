package com.github.aelstad.xoodoo;

public class TagValidationException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public TagValidationException() {
        super("Supplied tag had wrong length or did not match");
    }

}
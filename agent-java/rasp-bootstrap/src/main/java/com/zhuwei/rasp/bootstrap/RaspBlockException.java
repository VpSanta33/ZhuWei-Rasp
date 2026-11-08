package com.zhuwei.rasp.bootstrap;

/** Thrown into business code when RASP blocks a dangerous operation. */
public class RaspBlockException extends SecurityException {

    private static final long serialVersionUID = 1L;

    private final String requestId;
    private final String checkType;

    public RaspBlockException(String message, String checkType, String requestId) {
        super(message);
        this.checkType = checkType;
        this.requestId = requestId;
    }

    public String getRequestId() { return requestId; }

    public String getCheckType() { return checkType; }

    /** Skip stack capture: it is expensive and the stack is reported separately. */
    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }
}

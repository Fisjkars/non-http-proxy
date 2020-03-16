package josh.service.utils.python;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;

import org.python.core.PyBoolean;
import org.python.core.PyByteArray;
import org.python.core.PyObject;
import org.python.util.PythonInterpreter;

public class PythonMangler {

    private String pyCode;
    private PythonInterpreter interpreter;
    private ByteArrayOutputStream out;
    private ByteArrayOutputStream err;

    public PythonMangler() {
        this.out = new ByteArrayOutputStream();
        this.err = new ByteArrayOutputStream();
        this.interpreter = new PythonInterpreter();
        interpreter.setOut(out);
        interpreter.setErr(err);

        String path = System.getProperty("user.home");
        String file = path + "/.NoPEProxy/mangler.py";

        File f = new File(file);
        if (!f.exists()) {
            try {
                f.createNewFile();
            } catch (IOException e) {
            }
        }
        Path p = Paths.get(file);

        pyCode = "";
        try {
            BufferedReader reader = Files.newBufferedReader(p);

            String line;
            while ((line = reader.readLine()) != null) {
                pyCode += line + "\r\n";
            }
            if (pyCode.trim().equals("")) {
                pyCode = "def mangle(input, isC2S):\r\n";
                pyCode += "\treturn input";
                p = Paths.get(file);
                Charset charset = Charset.forName("UTF-8");
                try (BufferedWriter writer = Files.newBufferedWriter(p, charset)) {
                    writer.write(pyCode);
                } catch (Exception ex) {
                }
            }
        } catch (IOException e) {
            pyCode = "";
        }
    }

    public String getError() {
        String error = err.toString();
        err = new ByteArrayOutputStream();
        return error;
    }

    public String getOutput() {
        String tmp = out.toString();
        out = new ByteArrayOutputStream();
        return tmp;
    }

    public static HashMap<String, Object> runRepeaterCode(String code) {
        HashMap<String, Object> outputs = new HashMap<>();
        PythonInterpreter interpreter = new PythonInterpreter();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        interpreter.setOut(out);
        interpreter.setErr(err);
        String JavaError = "";
        byte[] output;
        try {
            interpreter.exec(code);
            PyObject someFunc = interpreter.get("sendPayload");
            if (someFunc == null) {
                return null;
            }
            PyObject result = someFunc.__call__();
            PyByteArray array = (PyByteArray) result.__tojava__(Object.class);

            output = new byte[array.__len__()];
            for (int i = 0; i < array.__len__(); i++) {
                output[i] = (byte) array.get(i).__tojava__(Byte.class);
            }

        } catch (Exception ex) {
            JavaError = ex.getLocalizedMessage();
            output = null;
        }

        outputs.put("out", output);
        outputs.put("stdout", out.toString());
        outputs.put("stderr", JavaError + "\n\n" + err.toString());
        return outputs;
    }

    public String getPyCode() {
        return pyCode.replaceAll("\r", "");
    }

    public String setPyCode(String code) {
        String path = System.getProperty("user.home");
        String file = path + "/.NoPEProxy/mangler.py";
        this.pyCode = code;
        if (pyCode.trim().equals("")) {
            pyCode = "def mangle(input, isC2S):\n";
            pyCode += "\treturn input\n";
        }
        Path p = Paths.get(file);
        Charset charset = Charset.forName("UTF-8");
        try (BufferedWriter writer = Files.newBufferedWriter(p, charset)) {
            writer.write(pyCode.replaceAll("\r", ""));
        } catch (Exception ex) {
        }
        return this.pyCode;
    }

    public byte[] preIntercept(byte[] input, boolean isC2S) {
        byte[] original = input;
        try {
            PyObject someFunc = interpreter.get("preIntercept");
            if (someFunc == null) {
                return input;
            }
            PyObject result = someFunc.__call__(new PyByteArray(input), new PyBoolean(isC2S));
            PyByteArray array = (PyByteArray) result.__tojava__(Object.class);

            byte[] out = new byte[array.__len__()];
            for (int i = 0; i < array.__len__(); i++) {
                out[i] = (byte) array.get(i).__tojava__(Byte.class);
            }

            return out;
        } catch (Exception ex) {
            return original;
        }
    }

    public byte[] postIntercept(byte[] input, boolean isC2S) {
        //PythonInterpreter interpreter = new PythonInterpreter();
        byte[] original = input;
        try {
            PyObject someFunc = interpreter.get("postIntercept");
            //this means that the post Intercept feature has not been implemented.
            if (someFunc == null) {
                return input;
            }
            PyObject result = someFunc.__call__(new PyByteArray(input), new PyBoolean(isC2S));
            PyByteArray array = (PyByteArray) result.__tojava__(Object.class);

            byte[] out = new byte[array.__len__()];
            for (int i = 0; i < array.__len__(); i++) {
                out[i] = (byte) array.get(i).__tojava__(Byte.class);
            }
            return out;
        } catch (Exception ex) {
            return original;
        }

    }

    public byte[] mangle(byte[] input, boolean isC2S) {
        byte[] original = input;
        try {
            interpreter.exec(pyCode);
            PyObject someFunc = interpreter.get("mangle");
            //this means that the mangle feature has not been implemented.
            if (someFunc == null) {
                return input;
            }
            PyObject result = someFunc.__call__(new PyByteArray(input), new PyBoolean(isC2S));
            PyByteArray array = (PyByteArray) result.__tojava__(Object.class);

            byte[] out = new byte[array.__len__()];
            for (int i = 0; i < array.__len__(); i++) {
                out[i] = (byte) array.get(i).__tojava__(Byte.class);
            }

            return out;
        } catch (Exception ex) {
            return original;
        }
    }
}

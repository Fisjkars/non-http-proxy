package zjosh.utils.events;

import java.util.EventListener;

public interface PythonOutputEventListener extends EventListener {

    public abstract void pythonMessages(PythonOutputEvent e);

}

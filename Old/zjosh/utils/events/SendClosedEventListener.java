package zjosh.utils.events;

import java.util.EventListener;

public interface SendClosedEventListener extends EventListener {

    public abstract void closed(SendClosedEvent e);

}

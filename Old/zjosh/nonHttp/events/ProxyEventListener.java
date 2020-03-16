package zjosh.nonHttp.events;

public interface ProxyEventListener {

    public abstract void dataReceived(ProxyEvent e);

    public abstract void intercepted(ProxyEvent e, boolean isC2S);

}

package josh.dao.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

/**
 * Listener Setting entity.
 */
@Entity
@Table(name = "ListenerSetting")
public class ListenerSettingEntity implements Serializable {

    @Id
    @Column(name = "id")
    @GeneratedValue
    private int id;

    @Column(name = "lport")
    private int lport;

    @Column(name = "sport")
    private int sport;

    @Column(name = "sip")
    private String sip;

    @Column(name = "cert")
    private String cert;

    @Column(name = "ssl")
    private boolean ssl;

    /**
     * Public constructor.
     */
    public ListenerSettingEntity() {
    }

    /**
     * Public constructor.
     *
     * @param lport Listener Port.
     * @param sport Server port.
     * @param sip Server ip.
     * @param cert Certificate Hostname.
     * @param ssl Is using SSL.
     */
    public ListenerSettingEntity(int lport, int sport, String sip, String cert, boolean ssl) {
        this.lport = lport;
        this.sport = sport;
        this.sip = sip;
        this.cert = cert;
        this.ssl = ssl;
    }

    /**
     * Listener Setting id.
     *
     * @return Listener Setting id.
     */
    public int getId() {
        return id;
    }

    /**
     * Listener Setting id.
     *
     * @param id Listener Setting id.
     */
    public void setId(int id) {
        this.id = id;
    }

    /**
     * Listener Port.
     *
     * @return Listener Port.
     */
    public int getLport() {
        return lport;
    }

    /**
     * Listener Port.
     *
     * @param lport Listener Port.
     */
    public void setLport(int lport) {
        this.lport = lport;
    }

    /**
     * Server port.
     *
     * @return Server port.
     */
    public int getSport() {
        return sport;
    }

    /**
     * Server port.
     *
     * @param sport Server port.
     */
    public void setSport(int sport) {
        this.sport = sport;
    }

    /**
     * Server ip.
     *
     * @return Server ip.
     */
    public String getSip() {
        return sip;
    }

    /**
     * Server ip.
     *
     * @param sip Server ip.
     */
    public void setSip(String sip) {
        this.sip = sip;
    }

    /**
     * Certificate Hostname.
     *
     * @return Certificate Hostname.
     */
    public String getCert() {
        return cert;
    }

    /**
     * Certificate Hostname.
     *
     * @param cert Certificate Hostname.
     */
    public void setCert(String cert) {
        this.cert = cert;
    }

    /**
     * Is using SSL.
     *
     * @return Is using SSL.
     */
    public boolean isSsl() {
        return ssl;
    }

    /**
     * Is using SSL.
     *
     * @param ssl Is using SSL.
     */
    public void setSsl(boolean ssl) {
        this.ssl = ssl;
    }

}

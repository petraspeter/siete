import java.sql.Timestamp;

public class Sprava {
	
	private String senderIp;
	
	private String senderMac;
	
	private Timestamp recivedTime;

	@Override
	public String toString() {
		return "Sender IP: " + senderIp + ",\t Sender MAC: " + senderMac + ",\t Recived time: " + recivedTime;
	}

	public String getSenderIp() {
		return senderIp;
	}

	public void setSenderIp(String senderIp) {
		this.senderIp = senderIp;
	}

	public String getSenderMac() {
		return senderMac;
	}

	public void setSenderMac(String senderMac) {
		this.senderMac = senderMac;
	}

	public Timestamp getRecivedTime() {
		return recivedTime;
	}

	public void setRecivedTime(Timestamp recivedTime) {
		this.recivedTime = recivedTime;
	}

	public Sprava(String senderIp, String senderMac, Timestamp recivedTime) {
		super();
		this.senderIp = senderIp;
		this.senderMac = senderMac;
		this.recivedTime = recivedTime;
	}

	public Sprava() {
		super();
	}
	
}

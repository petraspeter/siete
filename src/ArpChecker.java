import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;

public class ArpChecker {

	public static void main(String[] args) {

		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // sietovky
		StringBuilder errbuf = new StringBuilder(); // chyby

		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
			return;
		}

		System.out.println("Network devices found:");

		int pocitadloKariet = 0;
		for (PcapIf device : alldevs) {
			String description = (device.getDescription() != null) ? device.getDescription()
					: "No description available";
			System.out.printf("#%d: %s [%s]\n", pocitadloKariet++, device.getName(), description);
		}

		/*
		 * treba zmenit na cislo pouzivanej sietovky
		 */
		PcapIf device = alldevs.get(1);
		System.out.printf("\nChoosing '%s' on your behalf:\n",
				(device.getDescription() != null) ? device.getDescription() : device.getName());
		int snaplen = 64 * 1024; // horne ohranicenie paketov
		int flags = Pcap.MODE_PROMISCUOUS; // zobrazujeme pakety, ktore su urcene pre inu MAC ako nasu
		int timeout = 3 * 1000; // ako dlho cakame na packet pokial ho spracuvavame, minimalne 1 mills
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

		if (pcap == null) {
			System.err.printf("Error while opening device for capture: " + errbuf.toString());
			return;
		}

		// zoznam sprav o adresach odosielatela(ip, mac, cas prijatia)
		List<Sprava> spravy = new ArrayList<>();
		// zoznam konfliktnych ip adries
		Set<String> nedoveryhodne = new HashSet<>();
				
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

			public void nextPacket(PcapPacket packet, String user) {
				Sprava sprava;
				Arp arp = new Arp();
				if (packet.hasHeader(arp)) {
					// informacie o odosielatelovi
					String senderMac = JNetPcapUtilities.getMacFromBytes(arp.sha());
					String senderIp = JNetPcapUtilities.getMacFromBytes(arp.spa());
					// informacie o prijemcovi
					String targetMac = JNetPcapUtilities.getMacFromBytes(arp.tha());
					String targetIp = JNetPcapUtilities.getMacFromBytes(arp.tpa());
					// z aktualneho paketu vyberieme informacie o odosielatelovi
					sprava = new Sprava(senderIp, senderMac, new Timestamp(System.currentTimeMillis()));
					/*
					System.out.println("--------------------------------------------------------");				 
					 */
					// prejdeme si zoznamom pirajtych paketov za poslednych 10 minut
					for (int i = 0; i < spravy.size(); i++) {
						// overujeme ci aktualna sprava nema rovnaku IP adresu a rozdielnu MAC, ak ano tak vypiseme upozornenie
						// a pridame IP medzi nedoveryhodne
						if (senderIp.equals(spravy.get(i).getSenderIp())
								&& !senderMac.equals(spravy.get(i).getSenderMac()) && (sprava.getRecivedTime().getTime()
										- spravy.get(i).getRecivedTime().getTime() < 60000)) 
						{
							System.out.println("V sieti sa moze nachadzat utocnik!");
							// pridame konfliktnu adresu medzi nedoveryhodne
							nedoveryhodne.add(sprava.getSenderIp());
						}
						// ak je sprava starsia ako 10 minut, tak ju vymazeme
						if (sprava.getRecivedTime().getTime() - spravy.get(i).getRecivedTime().getTime() >= 60000) {
							spravy.remove(i);
						}
						/*
						System.out.println(spravy.get(i).toString());
						 */
					}
					// pridame spravu do zoznamu
					if (sprava != null) {
						spravy.add(sprava);
					}
				}
			}
		};

		pcap.loop(-7, jpacketHandler, "handler");
		pcap.close();
	}
}
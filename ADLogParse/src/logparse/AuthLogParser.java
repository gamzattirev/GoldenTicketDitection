package logparse;

import java.io.*;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * Detect mimikatz comparing Common DLL List with exported Sysmon event log.
 * Output processes that load all DLLs in Common DLL List and detection rate.
 * 
 * @version 1.0
 * @author Mariko Fujimoto
 */
public class AuthLogParser {

	/**
	 * Specify file name of mimikatz
	 */
	private static Map<String, HashSet> log;
	private static String outputDirName = null;
	private static List<String> SUSPICIOUS_CMD = null;
	private Set<String> accounts=new HashSet<String>();
	
	static{
		SUSPICIOUS_CMD=new ArrayList<String>();
		SUSPICIOUS_CMD.add("dir");
		SUSPICIOUS_CMD.add("hostname");
		SUSPICIOUS_CMD.add("whoami");
		SUSPICIOUS_CMD.add("net use");
	}

	private void readCSV(String filename) {

		try {
			File f = new File(filename);
			BufferedReader br = new BufferedReader(new FileReader(f));
			String line;
			int eventID = -1;
			String date = "";
			HashSet<EventLogData> evSet = null;
			String accountName = "";
			String clientAddress = "";
			String serviceName = "";
			String processName = "";
			int limit=0;
			while ((line = br.readLine()) != null) {
				int clientPort=0;
				line=line.replaceAll("\\t", "");
				String[] data = line.split(",", 0);
				for (String elem : data) {
					if (line.contains("Microsoft-Windows-Security-Auditing,4769")
							|| line.contains("Microsoft-Windows-Security-Auditing,4768")
							|| line.contains("Microsoft-Windows-Security-Auditing,4674")
							|| line.contains("Microsoft-Windows-Security-Auditing,4672")) {
						date = data[1];
						eventID = Integer.parseInt(data[3]);
					} else if (elem.contains("アカウント名:")||elem.contains("Account Name:")) {
						accountName = parseElement(elem, ":",limit);
						if (accountName.isEmpty()) {
							continue;
						} else {
							accountName = accountName.split("@")[0].toLowerCase();
							if(4672==eventID){
								evSet.add(new EventLogData(date, "", accountName, eventID, 0, "",""));
								log.put(accountName, evSet);
								eventID = -1;
								accounts.add(accountName);
								continue;
							}
						}
						if (null == log.get(accountName)) {
							evSet = new HashSet<EventLogData>();
						} else {
							evSet = log.get(accountName);
						}
					} else if (elem.contains("サービス名:")||elem.contains("Service Name:")) {
						serviceName = parseElement(elem, ":",limit);
					} else if (elem.contains("クライアント アドレス:")||elem.contains("Client Address:")) {
						elem=elem.replaceAll("::ffff:", "");
						clientAddress = parseElement(elem, ":",limit);
					} else if ((elem.contains("クライアント ポート:") ||elem.contains("Client Port:"))&& 0 <=eventID) {
						clientPort = Integer.parseInt(parseElement(elem, ":",limit));
						evSet.add(new EventLogData(date, clientAddress, accountName, eventID, clientPort, serviceName,processName));
						log.put(accountName, evSet);
						eventID = -1;
						serviceName="";
					} else if ((elem.contains("プロセス名:")||elem.contains("Process Name:")) && 0 <=eventID) {
						processName = parseElement(elem, ":",2).toLowerCase();
						evSet.add(new EventLogData(date, clientAddress, accountName, eventID, clientPort, serviceName,processName));
						log.put(accountName, evSet);
						eventID = -1;
						processName = "";
					} 
				}
			}
			br.close();

		} catch (IOException e) {
			System.out.println(e);
		}

	}

	private String parseElement(String elem, String delimiter, int limit) {
		String value = "";
		try {
			String elems[] = elem.trim().split(delimiter,limit);
			if (elems.length >= 2) {
				value = elems[1];
				value = value.replaceAll("\t", "");
			}
		} catch (RuntimeException e) {
			System.out.println(elem);
			e.printStackTrace();
		}
		return value;
	}

	private void outputResults(Map map, String outputFileName) {

		//アカウントごとに調べる
		for (Iterator it = map.entrySet().iterator(); it.hasNext();) {
			Map.Entry<String, HashSet> entry = (Map.Entry<String, HashSet>) it.next();
			String accountName = (String) entry.getKey();
			if (!accounts.contains(accountName)) {
				continue;
			}
			HashSet<EventLogData> evS = (HashSet<EventLogData>) entry.getValue();
			HashSet<String> imageLoadedList = new HashSet<String>();
			Map<String, HashSet> kerlog = new HashMap<String, HashSet>();

			// クライアントアドレスごとにマップへ入れる
			for (EventLogData ev : evS) {
				HashSet<EventLogData> evSet;
				if (null != kerlog.get(ev.getClientAddress())) {
					evSet = kerlog.get(ev.getClientAddress());
				} else {
					evSet = new HashSet<EventLogData>();
				}
				evSet.add(ev);
				kerlog.put(ev.getClientAddress(), evSet);
			}
			isGoldenUsed(kerlog, outputFileName);
		}

	}

	private void isGoldenUsed(Map<String, HashSet> kerlog, String outputFileName) {
		// 
		File file = new File(outputFileName);
		FileWriter filewriter = null;
		BufferedWriter bw = null;
		PrintWriter pw = null;
		try {
			filewriter = new FileWriter(file,true);
			bw = new BufferedWriter(filewriter);
			pw = new PrintWriter(bw);
			for (Iterator it = kerlog.entrySet().iterator(); it.hasNext();) {
				// アカウント、端末ごとに4768/4769
				boolean isTGTEvent = false;
				boolean isSTEvent = false;
				boolean isGolden = false;
				Map.Entry<String, HashSet> entry = (Map.Entry<String, HashSet>) it.next();
				HashSet<EventLogData> evS = (HashSet<EventLogData>) entry.getValue();
				for (EventLogData ev : evS) {
					int eventID = ev.getEventID();
					if (eventID == 4768) {
						isTGTEvent = true;
					} else if (eventID == 4769) {
						isSTEvent = true;
					}
				}
				if (!isTGTEvent && isSTEvent) {
					isGolden = true;
				} 
				for (EventLogData ev : evS) {
					for (String cmd : SUSPICIOUS_CMD){
						if (ev.getProcessName().contains(cmd)){
							isGolden = true;
						}
					}
					pw.println(ev.getEventID() + ", " + ev.getDate() + ", "+ ev.getAccountName() + "," + ev.getClientAddress() + ", "
							+ev.getClientPort()+ ", " +ev.getServiceName() + ", " +ev.getProcessName() + ", " + isGolden);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			pw.close();
			try {
				bw.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

	}

	/**
	 * Parse CSV files exported from Sysmon event log. Output process/loaded
	 * DLLs and detect which matches Common DLL List.
	 * 
	 * @param inputDirname
	 */
	public void detectGolden(String inputDirname) {
		File dir = new File(inputDirname);
		File[] files = dir.listFiles();

		for (File file : files) {
			String filename = file.getName();
			if (filename.endsWith(".csv")) {
				readCSV(file.getAbsolutePath());
			} else {
				continue;
			}
			outputResults(log, this.outputDirName + "/" + "result.csv");
		}

	}

	private void detelePrevFiles(String outDirname) {
		Path path = Paths.get(outDirname);
		try (DirectoryStream<Path> ds = Files.newDirectoryStream(path, "*.*")) {
			for (Path deleteFilePath : ds) {
				Files.delete(deleteFilePath);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void printUseage() {
		System.out.println("Useage");
		System.out.println("{iputdirpath} {Common DLL List path} {outputdirpath} (-dr)");
		System.out.println("If you evaluate detection rate using Common DLL Lists specify -dr option.)");
	}

	public static void main(String args[]) {
		AuthLogParser sysmonParser = new AuthLogParser();
		String inputdirname = "";
		if (args.length < 2) {
			printUseage();
		} else if (args.length > 0) {
			inputdirname = args[0];
		}

		if (args.length > 1) {
			outputDirName = args[1];
		}
		log = new HashMap<String, HashSet>();
		sysmonParser.detelePrevFiles(outputDirName);
		sysmonParser.detectGolden(inputdirname);
	}

}
package logparse;

import java.io.*;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.*;
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
	private static Map<String, LinkedHashSet> log;
	private static String outputDirName = null;
	private static short TIME_CNT = Short.MAX_VALUE;
	private static float TRAIN_PERCENTAGE=0.75f;
	private List<String> SUSPICIOUS_CMD = null;
	private Set<String> accounts = new LinkedHashSet<String>();
	private FileWriter filewriter = null;
	private BufferedWriter bw = null;
	private PrintWriter pw = null;
	private FileWriter filewriter2 = null;
	private BufferedWriter bw2 = null;
	private PrintWriter pw2 = null;
	private FileWriter filewriter3 = null;
	private BufferedWriter bw3 = null;
	private PrintWriter pw3 = null;
	private SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
	private int logCnt=0;
	private int trainNum=0;
	private int currentTrainNum=0;
	private int currentTrainNum2=0;
	private long id=0;
	// private SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy hh:mm:ss
	// a");

	private void readCSV(String filename) {

		try {
			File f = new File(filename);
			BufferedReader br = new BufferedReader(new FileReader(f));
			String line;
			int eventID = -1;
			String date = "";
			//時刻順に格納する
			LinkedHashSet<EventLogData> evSet = null;
			String accountName = "";
			String clientAddress = "";
			String serviceName = "";
			String processName = "";
			int limit = 0;
			Date baseDate = null;
			Date logDate = null;
			short timeCnt = TIME_CNT;
			SimpleDateFormat sdfOut = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
			boolean isTargetEvent = false;
			while ((line = br.readLine()) != null) {
				int clientPort = 0;
				line = line.replaceAll("\\t", "");
				String[] data = line.split(",", 0);
				for (String elem : data) {
					if (line.contains("Microsoft-Windows-Security-Auditing,")) {
						date = data[1];
						eventID = Integer.parseInt(data[3]);
					}
					if (line.contains("Microsoft-Windows-Security-Auditing,4769")
							|| line.contains("Microsoft-Windows-Security-Auditing,4768")
							|| line.contains("Microsoft-Windows-Security-Auditing,4674")
							|| line.contains("Microsoft-Windows-Security-Auditing,4672")
							|| line.contains("Microsoft-Windows-Security-Auditing,4624")) {
						isTargetEvent = true;
						try {
							logDate = sdf.parse(date);

							if (4769 == eventID && null == baseDate) {
								baseDate = sdf.parse(date);
								timeCnt--;
							} else if (null != baseDate) {
								long logTime = logDate.getTime();
								long baseTime = baseDate.getTime();
								long timeDiff = (baseTime - logTime) / 1000;
								// System.out.println(date+","+logDate+","+logDate.getTime()/1000L);
								if (timeDiff > 1) {
									timeCnt--;
									baseDate = sdf.parse(date);
								}
							}

						} catch (ParseException e) {
							e.printStackTrace();
						}

					} else if (isTargetEvent) {
						if (elem.contains("アカウント名:") || elem.contains("Account Name:")) {
							accountName = parseElement(elem, ":", limit);

							if (accountName.isEmpty()) {
								continue;
							} else {
								accountName = accountName.split("@")[0].toLowerCase();
								if (null == log.get(accountName)) {
									evSet = new LinkedHashSet<EventLogData>();
								} else {
									evSet = log.get(accountName);
								}
								if (4672 == eventID) {
									evSet.add(new EventLogData(date, "", accountName, eventID, 0, "", "", timeCnt));
									log.put(accountName, evSet);
									//logCnt++;
									eventID = -1;
									accounts.add(accountName);
									continue;
								}
							}

						} else if (elem.contains("サービス名:") || elem.contains("Service Name:")) {
							serviceName = parseElement(elem, ":", limit);
						} else if (elem.contains("クライアント アドレス:") || elem.contains("Client Address:")
								|| elem.contains("ソース ネットワーク アドレス:")) {
							elem = elem.replaceAll("::ffff:", "");
							clientAddress = parseElement(elem, ":", limit);
							if (clientAddress.isEmpty()) {
								clientAddress = "0";
							}

						} else if ((elem.contains("クライアント ポート:") || elem.contains("Client Port:")
								|| elem.contains("ソース ポート:")) && 0 <= eventID) {
							clientPort = Integer.parseInt(parseElement(elem, ":", limit));
							evSet.add(new EventLogData(date, clientAddress, accountName, eventID, clientPort,
									serviceName, processName, timeCnt));
							log.put(accountName, evSet);
							//logCnt++;
							eventID = -1;
							serviceName = "";
						} else if ((elem.contains("プロセス名:") || elem.contains("Process Name:")) && 0 <= eventID) {
							processName = parseElement(elem, ":", 2).toLowerCase();
							evSet.add(new EventLogData(date, clientAddress, accountName, eventID, clientPort,
									serviceName, processName, timeCnt));
							log.put(accountName, evSet);
							//logCnt++;
							eventID = -1;
							processName = "";
						}
					} else {
						isTargetEvent = false;
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
			String elems[] = elem.trim().split(delimiter, limit);
			if (elems.length >= 2) {
				value = elems[1];
				value = value.replaceAll("\t", "");
			}
		} catch (RuntimeException e) {
			System.out.println(elem);
			e.printStackTrace();
		}
		if (value.isEmpty()) {
			value = "";
		} 
		/*
		else if (value.equals("-")) {
			value = "";
		}
		*/
		return value;
	}

	private void outputResults(Map map, String outputFileName) {
		try {
			filewriter = new FileWriter(outputFileName, true);
			bw = new BufferedWriter(filewriter);
			pw = new PrintWriter(bw);
			//pw.println("date_utime,eventID,account,ip,port,service,process,timeCnt,target");
			pw.println("date,date_utime,eventID,account,ip,port,service,process,timeCnt,target");

			filewriter2 = new FileWriter(outputDirName + "/" + "mergedlog.csv" + "", true);
			bw2 = new BufferedWriter(filewriter2);
			pw2 = new PrintWriter(bw2);
			// pw.println("date,date_utime,eventID,account,ip,port,service,process,timeCnt,target");
			pw2.println("eventID,account,ip,port,service,process,target");
			
			filewriter3 = new FileWriter(outputDirName + "/" + "timeseriselog.csv" + "", true);
			bw3 = new BufferedWriter(filewriter3);
			pw3 = new PrintWriter(bw3);
			//pw.println("date_utime,eventID,account,ip,port,service,process,timeCnt,target");
			pw3.println("id,eventID_p,account_p,ip_p,service_p,process_p,"
					+ "eventID_c,account_c,ip_c,service_c,process_c,target");
			
			ArrayList <EventLogData> list=null;
			
			// アカウントごとに分類する
			for (Iterator it = map.entrySet().iterator(); it.hasNext();) {
				Map.Entry<String, LinkedHashSet> entry = (Map.Entry<String, LinkedHashSet>) it.next();
				String accountName = (String) entry.getKey();
				if (!accounts.contains(accountName)) {
					//特権を使っているアカウントのみ抽出
					continue;
				}
				LinkedHashSet<EventLogData> evS = (LinkedHashSet<EventLogData>) entry.getValue();
				Map<String, LinkedHashSet> kerlog = new LinkedHashMap<String, LinkedHashSet>();
				Map<Long, LinkedHashSet> timeBasedlog = new LinkedHashMap<Long, LinkedHashSet>();

				// さらにクライアントアドレスごとに分類し、GTが使われている可能性があるかを判定する
				for (EventLogData ev : evS) {
					LinkedHashSet<EventLogData> evSet;
					if (null != kerlog.get(ev.getClientAddress())) {
						evSet = kerlog.get(ev.getClientAddress());
					} else {
						evSet = new LinkedHashSet<EventLogData>();
					}
					evSet.add(ev);
					kerlog.put(ev.getClientAddress(), evSet);
					this.logCnt++;
				}
				isGoldenUsed(kerlog);

				// 同じ時間帯のログごとに処理
				list=new ArrayList <EventLogData>(evS);
				Collections.reverse(list);
				for (EventLogData ev : list) {
					LinkedHashSet<EventLogData> evSet;
					if (null != timeBasedlog.get(ev.getTimeCnt())) {
						evSet = timeBasedlog.get(ev.getTimeCnt());
					} else {
						evSet = new LinkedHashSet<EventLogData>();
					}
					evSet.add(ev);
					timeBasedlog.put(ev.getTimeCnt(), evSet);
				}
				this.trainNum=Math.round(this.logCnt*this.TRAIN_PERCENTAGE);
				//ファイルに出力する
				outputLogs(timeBasedlog, accountName);
				// time seriesログを出力する
				outputTimeSeriseLogs(timeBasedlog, accountName);
				//マージする
				mergeLogs(timeBasedlog, accountName);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			pw.close();
			pw2.close();
			pw3.close();
			try {
				bw.close();
				bw2.close();
				bw3.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private void isGoldenUsed(Map<String, LinkedHashSet> kerlog) {
		// kerlogは端末毎に分類されたログ
		for (Iterator it = kerlog.entrySet().iterator(); it.hasNext();) {
			boolean isTGTEvent = false;
			boolean isSTEvent = false;
			short isGolden = 0;
			Map.Entry<String, LinkedHashSet> entry = (Map.Entry<String, LinkedHashSet>) it.next();
			LinkedHashSet<EventLogData> evS = (LinkedHashSet<EventLogData>) entry.getValue();
			for (EventLogData ev : evS) {
				int eventID = ev.getEventID();
				// 4768/4769が記録されているかを調べる
				if (eventID == 4768) {
					isTGTEvent = true;
				} else if (eventID == 4769) {
					isSTEvent = true;
				}
			}
			if (!isTGTEvent && isSTEvent) {
				// 4768が記録されていないのに、4769が記録されている
				isGolden = 1;
				for (EventLogData ev : evS) {
					ev.setIsGolden(isGolden);
					this.logCnt--;
				}
			}
			for (EventLogData ev : evS) {
				for (String cmd : SUSPICIOUS_CMD) {
					if (ev.getProcessName().contains(cmd)) {
						isGolden = 1;
						ev.setIsGolden(isGolden);
						this.logCnt--;
					}
				}
				// 同じアカウント・端末・時間帯のログに同じtimeCntを割り当てる
				long timeCnt = (ev.getAccountName() + ev.getClientAddress()).hashCode() + ev.getTimeCnt();
				ev.settimeCnt(timeCnt);
			}
		}

	}

	private void mergeLogs(Map<Long, LinkedHashSet> kerlog, String accountName) {
		for (Iterator it = kerlog.entrySet().iterator(); it.hasNext();) {
			Map.Entry<Long, LinkedHashSet> entry = (Map.Entry<Long, LinkedHashSet>) it.next();
			LinkedHashSet<EventLogData> evS = (LinkedHashSet<EventLogData>) entry.getValue();
			Map<String, LinkedHashSet> map = new LinkedHashMap<String, LinkedHashSet>();
			LinkedHashSet<EventLogData> set = null;
			// 端末毎に分類する
			String clientAddress = "";
			for (EventLogData ev : evS) {
				if (!ev.getClientAddress().isEmpty()) {
					if (null != map.get(ev.getClientAddress())) {
						set = map.get(ev.getClientAddress());
					} else {
						set = new LinkedHashSet<EventLogData>();
					}
				} else {
					// 端末情報が出ないログは、直前に処理した端末と同じとみなす
					if (null != map.get(ev.getClientAddress())) {
						set = map.get(clientAddress);
					} else {
						set = new LinkedHashSet<EventLogData>();
					}
				}
				set.add(ev);
				map.put(ev.getClientAddress(), set);
			}
			// 同じtimeCnt,IPのデータをマージする
			String event = "";
			int clientPort = 0;
			String serviceName = "";
			String processName = "";
			short isGolden=0;
			for (Iterator itTerm = map.entrySet().iterator(); itTerm.hasNext();) {
				Map.Entry<String, LinkedHashSet> entryTerm = (Map.Entry<String, LinkedHashSet>) itTerm.next();
				clientAddress = entryTerm.getKey();
				LinkedHashSet<EventLogData> evSTerm = (LinkedHashSet<EventLogData>) entryTerm.getValue();
				for (EventLogData ev : evS) {
					event = event += String.valueOf(ev.getEventID());
					clientPort = clientPort += ev.getClientPort();
					serviceName = serviceName += ev.getServiceName();
					processName = processName += ev.getProcessName();
					if(1==ev.isGolden()){
						isGolden=ev.isGolden();
					}
				}
				pw2.println(event + ", " + accountName + "," + clientAddress + ", " + clientPort + ", " + serviceName
						+ ", " + processName+ ", " +isGolden );
			}
		}

	}
	
	private void outputLogs(Map<Long, LinkedHashSet> kerlog, String accountName) {
		long timeCnt=0;
		ArrayList <EventLogData> list=null;
		for (Iterator it = kerlog.entrySet().iterator(); it.hasNext();) {
			Map.Entry<Long, LinkedHashSet> entry = (Map.Entry<Long, LinkedHashSet>) it.next();
			LinkedHashSet<EventLogData> evS = (LinkedHashSet<EventLogData>) entry.getValue();
			//list=new ArrayList <EventLogData>(evS);
			//Collections.reverse(list);
			String target="";		
				for (EventLogData ev : evS) {
					if(1==ev.isGolden()){
						target="outlier";
					} else if(currentTrainNum<=trainNum || timeCnt==ev.getTimeCnt()){
						target="train";
						currentTrainNum++;
					} else{
						target="test";
					}
					// UNIX Timeの計算
					long time = 0;
					try {
						time = sdf.parse(ev.getDate()).getTime();
					} catch (ParseException e) {
						e.printStackTrace();
					}
					 pw.println(ev.getDate()+"," +time+"," + ev.getEventID() +
							 "," + accountName + "," + ev.getClientAddress() +
							 "," + ev.getClientPort() + "," + ev.getServiceName() + ","
							 + ev.getProcessName() + "," + ev.getTimeCnt() + "," + target);
				}
				timeCnt=entry.getKey();
		}

	}
	
	private void outputTimeSeriseLogs(Map<Long, LinkedHashSet> kerlog, String accountName) {
		long timeCnt=0;
		ArrayList <EventLogData> list=null;
		for (Iterator it = kerlog.entrySet().iterator(); it.hasNext();) {
			Map.Entry<Long, LinkedHashSet> entry = (Map.Entry<Long, LinkedHashSet>) it.next();
			LinkedHashSet<EventLogData> evS = (LinkedHashSet<EventLogData>) entry.getValue();
			//list=new ArrayList <EventLogData>(evS);
			//Collections.reverse(list);
			String target="";
			EventLogData prevEv=null;
				for (EventLogData ev : evS) {
					if(1==ev.isGolden()){
						target="outlier";
					} else if(currentTrainNum2<=trainNum || timeCnt==ev.getTimeCnt()){
						target="train";
						currentTrainNum2++;
					} else{
						target="test";
					}
					this.id++;
					pw3.print(this.id+",");
					if(null==prevEv){
						 pw3.print("-,-,-,-,-");
					} else{
					 pw3.print(prevEv.getEventID() +"," + accountName + "," + prevEv.getClientAddress() +
							 "," + prevEv.getServiceName() + ","+ prevEv.getProcessName() );
					}
					 pw3.println("," + ev.getEventID() +"," + accountName + "," + ev.getClientAddress() +
							 "," + ev.getServiceName() + ","+ ev.getProcessName() 
							 + "," + target);
					 prevEv=new EventLogData(ev.getDate(),ev.getClientAddress(),accountName,ev.getEventID(),
							 ev.getClientPort(),ev.getServiceName(),ev.getProcessName(),ev.getTimeCnt());
				}
				timeCnt=entry.getKey();
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
	
	private  void createSuspiciousCmd(String inputdirname){
		
		File f = new File(inputdirname+"/command.txt");
		SUSPICIOUS_CMD = new ArrayList<String>();
		try {
			BufferedReader br = new BufferedReader(new FileReader(f));
			String line;
			while ((line = br.readLine()) != null) {
				SUSPICIOUS_CMD.add(line);
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

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
		log = new LinkedHashMap<String, LinkedHashSet>();
		sysmonParser.createSuspiciousCmd(inputdirname);
		sysmonParser.detelePrevFiles(outputDirName);
		sysmonParser.detectGolden(inputdirname);
	}

}

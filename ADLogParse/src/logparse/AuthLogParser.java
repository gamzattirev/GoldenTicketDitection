package logparse;

import java.io.*;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.*;
import java.util.*;

/**
 * Golden Ticket detection using Windows Event log.
 * 
 * @version 1.0
 * @author Mariko Fujimoto
 */
public class AuthLogParser {

	// キーはアカウント名、値はEventLogDataオブジェクトのリスト。アカウント毎に分類するため
	private static Map<String, LinkedHashSet<EventLogData>> log;
	private static String outputDirName = null;

	// Initial value for timeCnt
	private static short TIME_CNT = Short.MAX_VALUE;
	
	// Command execution rate for alert
	private static double ALERT_SEVIRE=0.7;
	private static double ALERT_WARNING=0.3;
	// Alert Level
	protected enum Alert{
		SEVERE,
		WARNING,
		NOTICE,
		NONE
	}

	// Suspicious command list
	private List<String> suspiciousCmd = null;

	// account name for detection(Domain Admin Privilege accounts)
	private Set<String> accounts = new LinkedHashSet<String>();
	
	private int detecctTargetcmdCnt=0;

	private FileWriter filewriter = null;
	private BufferedWriter bw = null;
	private PrintWriter pw = null;
	private FileWriter filewriter2 = null;
	private BufferedWriter bw2 = null;
	private PrintWriter pw2 = null;
	private FileWriter filewriter3 = null;
	private BufferedWriter bw3 = null;
	private PrintWriter pw3 = null;

	// Data format
	private static SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

	private int trainNum = 0;
	private int currentTrainNum2 = 0;
	private long id = 0;
	private static long attackStartTime = 0;
	private int logCnt = 0;
	private int eventNum=0;
	private int detectedNum=0;

	// Parameters for calculate number of train data(not used now)
	// private static float TRAIN_PERCENTAGE=0.75f;
	// private int currentTrainNum=0;

	private void readCSV(String filename) {

		try {
			File f = new File(filename);
			BufferedReader br = new BufferedReader(new FileReader(f));
			String line;
			int eventID = -1;
			String date = "";
			LinkedHashSet<EventLogData> evSet = null;
			String accountName = "";
			String clientAddress = "";
			String serviceName = "";
			String processName = "";
			boolean isTargetEvent = false;

			// splitする際の上限回数
			int limit = 0;

			// categorize same operations based on time stamp
			short timeCnt = TIME_CNT;
			Date baseDate = null;
			Date logDate = null;

			while ((line = br.readLine()) != null) {
				int clientPort = 0;
				// Remove tab
				line = line.replaceAll("\\t", "");
				String[] data = line.split(",", 0);
				for (String elem : data) {
					if (line.contains("Microsoft-Windows-Security-Auditing,")) {
						date = data[1];
						eventID = Integer.parseInt(data[3]);
						if (line.contains("4769") || line.contains("4768") || line.contains("4674")
								|| line.contains("4672") ||  line.contains("5140")
								|| line.contains("4673") || line.contains("4688")) {
							// Event for investigation
							eventNum++;
							isTargetEvent = true;
							try {
								// Get date
								logDate = sdf.parse(date);
								if (4769 == eventID && null == baseDate) {
									// 4769 を起点として同じ時間帯に出ているログを調べる
									baseDate = sdf.parse(date);
									timeCnt--;
								} else if (null != baseDate) {
									// ログのタイムスタンプ差を調べる
									long logTime = logDate.getTime();
									long baseTime = baseDate.getTime();
									long timeDiff = (baseTime - logTime) / 1000;
									if (timeDiff > 1) {
										// 1秒以上離れているログには異なるtimeCntを割り当てる
										timeCnt--;
										baseDate = sdf.parse(date);
									}
								}

							} catch (ParseException e) {
								e.printStackTrace();
							}
						} else{
							isTargetEvent = false;
						}
					} else if (isTargetEvent) {
						if (elem.contains("アカウント名:") || elem.contains("Account Name:")) {
							accountName = parseElement(elem, ":", limit);
							if (accountName.isEmpty()) {
								continue;
							} else {
								// ドメイン名は取り除き、全て小文字にする
								accountName = accountName.split("@")[0].toLowerCase();
								if (null == log.get(accountName)) {
									evSet = new LinkedHashSet<EventLogData>();
								} else {
									evSet = log.get(accountName);
								}
								if (4672 == eventID) {
									// 4672はこれ以上情報がないので、アカウント名だけ取得
									evSet.add(new EventLogData(date, "", accountName, eventID, 0, "", "", timeCnt));
									log.put(accountName, evSet);
									// 管理者アカウントリストに入れる
									accounts.add(accountName);
									continue;
								}
							}

						} else if (elem.contains("サービス名:") || elem.contains("Service Name:")) {
							serviceName = parseElement(elem, ":", limit);
						} else if (elem.contains("クライアント アドレス:") || elem.contains("Client Address:")
								|| elem.contains("ソース ネットワーク アドレス:") || elem.contains("送信元アドレス:")) {
							elem = elem.replaceAll("::ffff:", "");
							clientAddress = parseElement(elem, ":", limit);
							if (clientAddress.isEmpty()) {
								clientAddress = "0";
							}

						} else if ((elem.contains("クライアント ポート:") || elem.contains("Client Port:")
								|| elem.contains("ソース ポート:"))) {
							try {
								clientPort = Integer.parseInt(parseElement(elem, ":", limit));
							} catch (NumberFormatException e) {
								// nothing
							}
							evSet.add(new EventLogData(date, clientAddress, accountName, eventID, clientPort,
									serviceName, processName, timeCnt));
							if (5140 != eventID) {
								// 5140は共有名の情報を取得してから格納する
								log.put(accountName, evSet);
							}
						} else if ((elem.contains("プロセス名:") || elem.contains("Process Name:"))) {
							// プロセス名は":"が含まれることがあることを考慮
							processName = parseElement(elem, ":", 2).toLowerCase();
							evSet.add(new EventLogData(date, clientAddress, accountName, eventID, clientPort,
									serviceName, processName, timeCnt));
							log.put(accountName, evSet);
							processName = "";
						} else if (elem.contains("共有名:")) {
							// カラムを増やしたくないので、プロセス名に入れる
							processName = parseElement(elem, ":", 2).toLowerCase();
							evSet.add(new EventLogData(date, clientAddress, accountName, eventID, clientPort,
									serviceName, processName, timeCnt));
							log.put(accountName, evSet);
							processName = "";
						}
					}
					/*
					else {
						isTargetEvent = false;
					}
					*/
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
		 * else if (value.equals("-")) { value = ""; }
		 */
		return value;
	}

	private void outputResults(Map map, String outputFileName) {
		try {
			// normal result
			filewriter = new FileWriter(outputFileName, true);
			bw = new BufferedWriter(filewriter);
			pw = new PrintWriter(bw);
			// pw.println("date_utime,eventID,account,ip,port,service,process,timeCnt,target");
			pw.println("date,date_utime,eventID,account,ip,service,process,timeCnt,target,alert");

			// result of merged log based on timeCnt
			filewriter2 = new FileWriter(outputDirName + "/" + "mergedlog.csv" + "", true);
			bw2 = new BufferedWriter(filewriter2);
			pw2 = new PrintWriter(bw2);
			// pw.println("date,date_utime,eventID,account,ip,port,service,process,timeCnt,target");
			pw2.println("eventID,account,ip,port,service,process,target");

			// for time series analysis
			filewriter3 = new FileWriter(outputDirName + "/" + "timeserieslog.csv" + "", true);
			bw3 = new BufferedWriter(filewriter3);
			pw3 = new PrintWriter(bw3);
			// pw.println("date_utime,eventID,account,ip,port,service,process,timeCnt,target");
			pw3.println("id,eventID_p,account_p,ip_p,service_p,process_p,"
					+ "eventID_c,account_c,ip_c,service_c,process_c,target");

			ArrayList<EventLogData> list = null;
			
			// アカウントごとに処理する
			// 特権を使っているアカウントのみ抽出
			for(String accountName :accounts) {
				LinkedHashSet<EventLogData> evS = log.get(accountName);

				// クライアントアドレス毎にログを保持するためのリスト(キー：クライアントアドレス)
				Map<String, LinkedHashSet> kerlog = new LinkedHashMap<String, LinkedHashSet>();

				// 同じ時間帯毎にログを保持するためのリスト(キー：クライアントアドレス)
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
				// GTが使われているか判定
				isGoldenUsed(kerlog);

				// 同じ時間帯のログごとに処理
				list = new ArrayList<EventLogData>(evS);
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
				// Calculate number of train data
				// this.trainNum=Math.round(this.logCnt*this.TRAIN_PERCENTAGE);

				// 結果をファイルに出力する
				outputLogs(timeBasedlog, accountName);
				// time series機械学習用のログを出力する
				//outputTimeSeriseLogs(timeBasedlog, accountName);
				// 同じ時間帯のログをマージする
				//mergeLogs(timeBasedlog, accountName);
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
			//System.out.println(entry.getKey());
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
				long timeCnt;
				Set<Long> attackTimeCnt = new HashSet<Long>();
				for (EventLogData ev : evS) {
					if (4769 == ev.getEventID()) {
						ev.setIsGolden(isGolden);
						this.logCnt--;
						this.detectedNum++;
						// 同じ時間帯のログを抽出する
						attackTimeCnt.add(ev.getTimeCnt());
					}
				}
				
				for (EventLogData ev : evS) {
					if (attackTimeCnt.contains(ev.getTimeCnt())) {
						// 同じ時間帯のログは攻撃によって記録された可能性が高い
						ev.setIsGolden(isGolden);
						this.logCnt--;
						this.detectedNum++;
					}
				}
			}
			Set<String> commands = new LinkedHashSet<String>();
			for (EventLogData ev : evS) {
				if (5140 == ev.getEventID()) {
					// 管理共有が使用されている
					if (ev.getProcessName().contains("\\c$")) {
						isGolden = 1;
						ev.setIsGolden(isGolden);
						this.logCnt--;
						this.detectedNum++;
					}
				} else if (4673 == ev.getEventID()||4674 == ev.getEventID()||4688 == ev.getEventID()) {
					// 攻撃者がよく実行するコマンドを実行している
					for (String cmd : suspiciousCmd) {
						if (ev.getProcessName().contains(cmd)) {
							isGolden = 1;
							ev.setIsGolden(isGolden);
							this.logCnt--;
							this.detectedNum++;
							commands.add(ev.getProcessName());
						}
					}
				}
				// 同じアカウント・端末・時間帯のログに同じtimeCntを割り当てる
				// アカウント・端末を連結させた文字列のハッシュコードとタイムカウントを加算する
				long timeCnt = (ev.getAccountName() + ev.getClientAddress()).hashCode() + ev.getTimeCnt();
				ev.settimeCnt(timeCnt);
			}
			// 実行された不審なコマンドの種類数
			int detecctcmdCnt=commands.size();
			double commandExecuterate=(double)detecctcmdCnt/this.detecctTargetcmdCnt;
			Alert alertLevel=Alert.NONE;
			if(commandExecuterate>this.ALERT_SEVIRE){
				alertLevel=Alert.SEVERE;
			} else if(commandExecuterate>this.ALERT_WARNING){
				alertLevel=Alert.WARNING;
			} else if(commandExecuterate>0){
				alertLevel=Alert.NOTICE;
			} 
			for (EventLogData ev : evS) {
				ev.setAlertLevel(alertLevel);
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
			short isGolden = 0;
			for (Iterator itTerm = map.entrySet().iterator(); itTerm.hasNext();) {
				Map.Entry<String, LinkedHashSet> entryTerm = (Map.Entry<String, LinkedHashSet>) itTerm.next();
				clientAddress = entryTerm.getKey();
				LinkedHashSet<EventLogData> evSTerm = (LinkedHashSet<EventLogData>) entryTerm.getValue();
				for (EventLogData ev : evS) {
					event = event += String.valueOf(ev.getEventID());
					clientPort = clientPort += ev.getClientPort();
					serviceName = serviceName += ev.getServiceName();
					processName = processName += ev.getProcessName();
					if (1 == ev.isGolden()) {
						isGolden = ev.isGolden();
					}
				}
				pw2.println(event + ", " + accountName + "," + clientAddress + ", " + clientPort + ", " + serviceName
						+ ", " + processName + ", " + isGolden);
			}
		}

	}

	private void outputLogs(Map<Long, LinkedHashSet> kerlog, String accountName) {
		for (Iterator it = kerlog.entrySet().iterator(); it.hasNext();) {
			Map.Entry<Long, LinkedHashSet> entry = (Map.Entry<Long, LinkedHashSet>) it.next();
			LinkedHashSet<EventLogData> evS = (LinkedHashSet<EventLogData>) entry.getValue();
			String target = "";
			long logTime = 0;
			for (EventLogData ev : evS) {
				try {
					logTime = sdf.parse(ev.getDate()).getTime();
				} catch (ParseException e1) {
					e1.printStackTrace();
				}
				if (1 == ev.isGolden()) {
					target = "outlier";
				} else if (logTime < this.attackStartTime) {
					// 攻撃開始前は学習用データとする
					target = "train";
				} else {
					// 攻撃開始前はテストデータとする
					target = "test";
				}
				// UNIX Timeの計算
				long time = 0;
				try {
					time = sdf.parse(ev.getDate()).getTime();
				} catch (ParseException e) {
					e.printStackTrace();
				}
				pw.println(ev.getDate() + "," + time + "," + ev.getEventID() + "," + accountName + ","
						+ ev.getClientAddress() + "," + ev.getServiceName() + "," + ev.getProcessName() + ","
						+ ev.getTimeCnt() + "," + target+ "," + ev.getAlertLevel());
			}
		}

	}

	private void outputTimeSeriseLogs(Map<Long, LinkedHashSet> kerlog, String accountName) {
		long timeCnt = 0;
		for (Iterator it = kerlog.entrySet().iterator(); it.hasNext();) {
			Map.Entry<Long, LinkedHashSet> entry = (Map.Entry<Long, LinkedHashSet>) it.next();
			LinkedHashSet<EventLogData> evS = (LinkedHashSet<EventLogData>) entry.getValue();
			String target = "";
			EventLogData prevEv = null;
			for (EventLogData ev : evS) {
				if (1 == ev.isGolden()) {
					target = "outlier";
				} else if (currentTrainNum2 <= trainNum || timeCnt == ev.getTimeCnt()) {
					target = "train";
					currentTrainNum2++;
				} else {
					target = "test";
				}
				this.id++;
				pw3.print(this.id + ",");
				if (null == prevEv) {
					pw3.print("-,-,-,-,-");
				} else {
					pw3.print(prevEv.getEventID() + "," + accountName + "," + prevEv.getClientAddress() + ","
							+ prevEv.getServiceName() + "," + prevEv.getProcessName());
				}
				pw3.println("," + ev.getEventID() + "," + accountName + "," + ev.getClientAddress() + ","
						+ ev.getServiceName() + "," + ev.getProcessName() + "," + target);
				prevEv = new EventLogData(ev.getDate(), ev.getClientAddress(), accountName, ev.getEventID(),
						ev.getClientPort(), ev.getServiceName(), ev.getProcessName(), ev.getTimeCnt());
			}
			timeCnt = entry.getKey();
		}
	}

	/**
	 * Parse CSV files exported from event log. Detect possibility of attacks
	 * using Golden Ticket
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
		}
		outputResults(log, this.outputDirName + "/" + "result.csv");
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
		System.out.println("{iputdirpath} {outputdirpath} {suspicious command list file} ({date when attack starts})");
		System.out.println("Date shold be specified 'yyyy/MM/dd HH:mm:ss' format.)");
	}

	/**
	 * Read suspicious command list
	 * 
	 * @param inputfilename
	 */
	private void readSuspiciousCmd(String inputfilename) {

		File f = new File(inputfilename);
		suspiciousCmd = new ArrayList<String>();
		try {
			BufferedReader br = new BufferedReader(new FileReader(f));
			String line;
			while ((line = br.readLine()) != null) {
				suspiciousCmd.add(line);
			}
			this.detecctTargetcmdCnt=this.suspiciousCmd.size();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}
	
	private void outputDetectionRate(){
		double truePositiveRate=(double)this.detectedNum/this.eventNum;
		String truePositiveRateS = String.format("%.4f", truePositiveRate);
		double trueNegativeRate=(double)(this.eventNum-this.detectedNum)/this.eventNum;
		String trueNegativeRateS = String.format("%.4f", trueNegativeRate);
		
		System.out.println("Total amount of events: "+this.eventNum);
		System.out.println("True Positive counts: "+this.detectedNum);
		System.out.println("True Negative counts: "+(this.eventNum-this.detectedNum));
	}

	public static void main(String args[]) throws ParseException {
		AuthLogParser sysmonParser = new AuthLogParser();
		String inputdirname = "";
		String commandFile = "";
		if (args.length < 3) {
			printUseage();
		} else
			inputdirname = args[0];
		outputDirName = args[1];
		commandFile = args[2];
		if (args.length > 3) {
			attackStartTime = sdf.parse(args[3]).getTime();
		}
		log = new LinkedHashMap<String, LinkedHashSet<EventLogData>>();
		sysmonParser.readSuspiciousCmd(commandFile);
		sysmonParser.detelePrevFiles(outputDirName);
		sysmonParser.detectGolden(inputdirname);
		sysmonParser.outputDetectionRate();
	}

}

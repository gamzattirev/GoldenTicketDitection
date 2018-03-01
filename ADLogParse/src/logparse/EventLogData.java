package logparse;

public class EventLogData {
	
	private String date="";
	private String accountName="";
	private String clientAddress="";
	private int eventID;
	private int clientPort;
	private String serviceName = "";
	private String processName = "";
	private short timeCnt;
	
	EventLogData(String date, String clientAddress, String accountName, int eventID, int clientPort, String serviceName, 
			String processName,short timeCnt){
		this.date=date;
		this.accountName=accountName;
		this.clientAddress=clientAddress;
		this.eventID=eventID;
		this.clientPort=clientPort;
		this.serviceName=serviceName;
		this.processName=processName;
		this.timeCnt=timeCnt;
	}
	
	public void setDate(String date){
		this.date=date;
	}
	
	public void setAccountName(String accountName){
		this.accountName=accountName;
	}
	
	public String getDate(){
		return this.date;
	}
	
	public String getAccountName(){
		return this.accountName;
	}
	public String getClientAddress(){
		return this.clientAddress;
	}
	public int getEventID(){
		return this.eventID;
	}
	public int getClientPort(){
		return this.clientPort;
	}
	public String getServiceName(){
		return this.serviceName;
	}
	public String getProcessName(){
		return this.processName;
	}
	public short getTimeCnt(){
		return this.timeCnt;
	}
}

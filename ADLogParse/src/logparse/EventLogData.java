package logparse;

public class EventLogData {
	
	private String date="";
	private String accountName="";
	private String clientAddress="";
	private int eventID;
	
	EventLogData(String date, String clientAddress, String accountName, int eventID){
		this.date=date;
		this.accountName=accountName;
		this.clientAddress=clientAddress;
		this.eventID=eventID;
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

}

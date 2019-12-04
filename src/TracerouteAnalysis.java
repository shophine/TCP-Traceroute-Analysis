import java.io.*;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TracerouteAnalysis {
    public static void main(String[] args) {

        try{
            String filename = args[0];
            //removing blank lines from text file
            sanitizeInputFile(filename);

            File file = new File(filename);
            Scanner scanner = new Scanner(file);
            ArrayList<String> arrayList = new ArrayList<>();

            //seperating each line as a String
            while (scanner.hasNextLine()) {
                String temp = scanner.nextLine();
                arrayList.add(temp);
            }

            ArrayList<String> finalList = new ArrayList<>();
            String intr = "";
            for (int i = 0; i < arrayList.size(); i++) {
                String tempp = arrayList.get(i);

                if((Character.isDigit(tempp.charAt(0))) && i==0){
                    intr = intr.concat(tempp);
                }else if(Character.isDigit(tempp.charAt(0))){
                    finalList.add(intr);
                    intr = "";
                    intr = intr.concat(tempp);
                }else{
                    intr = intr.concat(tempp);
                }

            }
            //adding the last packet stored in buffer
            finalList.add(intr);

           /* //printing the arraylist
           for (int i = 0; i < finalList.size(); i++) {
              System.out.println("Packet : " + i + "\n" + finalList.get(i));
           }*/

            //seperating TCP and ICMP Packets
            ArrayList<String> icmpPackets = new ArrayList<>();
            ArrayList<String> tcpPackets = new ArrayList<>();
            for (int i = 0; i < finalList.size(); i++) {
                if (finalList.get(i).contains("proto ICMP")) {
                    // System.out.println("\n\tTCP packet :" + i + ": " + finalList.get(i));
                    icmpPackets.add(finalList.get(i));
                } else {
                    // System.out.println("\n\tICMP packet :" + i + ": " + finalList.get(i));
                    tcpPackets.add(finalList.get(i));
                }
            }
/*

            //System.out.println("\n\n\nPrinting the TCP packets : Size : " + tcpPackets.size());
            //printing the TCP packets
            for (String print : tcpPackets)
                System.out.println(print);

            //System.out.println("\n\n\nPrinting the ICMP packets : Size : " + icmpPackets.size());
            //printing the ICMP packets
            for (String print : icmpPackets)
                System.out.println(print);
*/

            //seperating ID from TCP packets
            ArrayList<Integer> idInTCP = new ArrayList<>();
            getIDFromPacket(idInTCP,tcpPackets);
            // System.out.println("ID in tco : "+idInTCP);

            //breaking the ICMP packet to find the TCP id
            ArrayList<String> brokenICMPPacket = new ArrayList<>();
            breakICPMPacket(icmpPackets,brokenICMPPacket);

            //System.out.println("\n\n\n\n\nPacket Broken : "+brokenICMPPacket);

            //seperating ID from ICMP packets
            ArrayList<Integer> idInICMP = new ArrayList<>();
            getIDFromBrokenICMPPacket(idInICMP,brokenICMPPacket);

            //if the id in TCP is 0 we won't have corresponding ICMP response
            //extracting only the TCP packets that has corresponding ICMP response
            //ignoring the TCP packets with id=0
            ArrayList<String> newTCPPackets = new ArrayList<>();
            for(int i=0;i<tcpPackets.size();i++){
                if(idInTCP.get(i)!=0){
                    newTCPPackets.add(tcpPackets.get(i));
                }
            }

            //extracting ttl from new TCP packet for RTT calculation
            ArrayList<Integer> ttl = new ArrayList<>();
            for (int i = 0; i < newTCPPackets.size(); i++) {
                ttl.add(getTTLfromTCPPacket(newTCPPackets, i));
            }

            //remove the duplicate ttl for iteration purpose
            ArrayList<Integer>ttlOrder = new ArrayList<>();
            ttlOrder = removeDuplicateTTL(ttl);

            ArrayList<Integer> packetNumberForTTL = new ArrayList<>();
            ArrayList<String> rttFinal = new ArrayList<>();

            int flag;
            //for every TTL
            for(int i=0;i<ttlOrder.size();i++){
                rttFinal.clear();
                flag=0;
                //Getting the corresponding TCP Packets
                getPacketNumbers(ttlOrder.get(i),tcpPackets,icmpPackets,packetNumberForTTL);

                for(int j=0;j<packetNumberForTTL.size();j++){
                    int pkNumber = packetNumberForTTL.get(j);
                    int idt = idInTCP.get(pkNumber);
                    for(int k=0;k<idInICMP.size();k++){

                        //Check the matching IP in ICMP Packets
                        if(idt==idInICMP.get(k)){
                            flag++;
                            String timeStamp2 = getTimeStampFromICMPPacket(icmpPackets,k);
                            String timeStamp1 = getTimeStampFromTCPPacket(tcpPackets,pkNumber);
                            String printableIP = getIPFromICMPPacket(icmpPackets,k);
                            String rtt = calculateRTT(timeStamp2, timeStamp1);
                            if(flag==1){
                                System.out.println("TTL "+ttlOrder.get(i));
                            }
                            //if the packet comes from different IP
                            if(!rttFinal.contains(printableIP)) {
                                System.out.println(printableIP);
                            }
                            System.out.println(rtt);
                            rttFinal.add(printableIP);
                        }
                    }
                }
                packetNumberForTTL.clear();
            }
        } catch (FileNotFoundException e) {
            System.out.println("File not found");
            e.printStackTrace();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    private static void sanitizeInputFile(String inputFile) {
        Scanner file;
        PrintWriter writer;
        try {
            file = new Scanner(new File(inputFile));
            writer = new PrintWriter("temp.txt");

            while (file.hasNext()) {
                String line = file.nextLine();
                if (!line.isEmpty()) {
                    writer.write(line);
                    writer.write("\n");
                }
            }
            file.close();
            writer.close();
        } catch (FileNotFoundException ex) {
            ex.printStackTrace();
        }
        File file1 = new File(inputFile);
        File file2 = new File("temp.txt");
        file1.delete();
        file2.renameTo(file1);
    }

    private static String  calculateRTT(String timeStamp2, String timeStamp1) {
        //System.out.println("TS 1: "+timeStamp1+"\t\tTS2: "+timeStamp2);
        double ts1 = Double.parseDouble(timeStamp1);
        double ts2 = Double.parseDouble(timeStamp2);
        double rtt = ts2-ts1;
        rtt=rtt*1000;

        BigDecimal bigDecimal = new BigDecimal(Double.toString(rtt));
        bigDecimal = bigDecimal.setScale(3, BigDecimal.ROUND_HALF_UP);
        DecimalFormat myFormatter = new DecimalFormat("0.000");
        String finalRTT = myFormatter.format(Double.parseDouble(bigDecimal.toString()));
       // System.out.println(finalRTT);

/*
        DecimalFormat df = new DecimalFormat("#.###");
        String finalRTT = df.format(rtt);
        return finalRTT+" ms";*/

        return finalRTT+" ms";

    }

    private static void breakICPMPacket(ArrayList<String> icmpPacket,ArrayList<String>brokenICMPPacket) {
        for(int i=0;i<icmpPacket.size();i++){
            String inputStr = icmpPacket.get(i);
            String regexStr = "proto ICMP(.*)id(.*), offset";
            Pattern pattern = Pattern.compile(regexStr);
            Matcher matcher = pattern.matcher(inputStr);
            if (matcher.find()) {
                //System.out.println(matcher.group(0));
                brokenICMPPacket.add(matcher.group(0));
            }
        }
    }

    private static void getIDFromBrokenICMPPacket(ArrayList<Integer> idInICMP, ArrayList<String>tcpPackets) {
        for(int i=0;i<tcpPackets.size();i++){
            String idTemp = tcpPackets.get(i).substring(tcpPackets.get(i).indexOf("id ")+3,tcpPackets.get(i).indexOf(", offset"));
            //System.out.println("ID: "+id);
            idInICMP.add(Integer.parseInt(idTemp));
        }
    }

    private static void getIDFromPacket(ArrayList<Integer> idInTCP, ArrayList<String>tcpPackets) {
        //getIDFromPacketTest(idInTCP,tcpPackets);
        for(int i=0;i<tcpPackets.size();i++){
            String idTemp = tcpPackets.get(i).substring(tcpPackets.get(i).indexOf("id ")+3,tcpPackets.get(i).indexOf(", offset"));
            //System.out.println("ID: "+id);
            idInTCP.add(Integer.parseInt(idTemp));
        }
    }

    private static void getPacketNumbers(int ttl,ArrayList<String>tcpPackets, ArrayList<String>icmpPackets,ArrayList<Integer>packetNumber) {
        String temp="";
        for(int i=0;i<tcpPackets.size();i++){
            String check="ttl "+ttl+",";
            if(tcpPackets.get(i).contains(check)){
                temp=temp.concat(Integer.toString(i)+" ");
                packetNumber.add(i);
            }
        }
    }

    private static ArrayList removeDuplicateTTL(ArrayList<Integer> ttl) {
        LinkedHashSet<Integer> hashSet = new LinkedHashSet<>(ttl);
        ArrayList<Integer> listWithoutDuplicates = new ArrayList<>(hashSet);
        //System.out.println(listWithoutDuplicates);
        return listWithoutDuplicates;
    }

    private static String getTimeStampFromICMPPacket(ArrayList<String> icmpPackets, int i) {
        String timeStamp = icmpPackets.get(i).substring(0, icmpPackets.get(i).indexOf(" IP ("));
        return timeStamp;
    }

    private static String getIPFromICMPPacket(ArrayList<String> icmpPackets, int i) {
        String inputStr = icmpPackets.get(i);
        String regexStr = "[0-9]+.[0-9]+.[0-9]+.[0-9]+\\s>\\s[0-9]+.[0-9]+.[0-9]+.[0-9]+: ICMP";            // Regex to be matched
        Pattern pattern = Pattern.compile(regexStr);
        Matcher matcher = pattern.matcher(inputStr);
        String IPfromICMP = "";
        if (matcher.find()) {
            //System.out.println(matcher.group(0));
            IPfromICMP = matcher.group(0);
        }
        String IP = getSenderIP(IPfromICMP);
        return IP;
    }

    private static String getSenderIP(String IPfromICMP) {
        String inputStr = IPfromICMP;
        String regexStr = "[0-9]+.[0-9]+.[0-9]+.[0-9]+";
        Pattern pattern = Pattern.compile(regexStr);
        Matcher matcher = pattern.matcher(inputStr);
        String IP = "";
        if (matcher.find()) {
            //System.out.println(matcher.group(0));
            IP = matcher.group(0);
        }
        return IP;
    }

    private static String getTimeStampFromTCPPacket(ArrayList<String> tcpPackets, int i) {
        String timeStamp = tcpPackets.get(i).substring(0, tcpPackets.get(i).indexOf(" IP ("));
        return timeStamp;
    }

    private static int getTTLfromTCPPacket(ArrayList<String> tcpPacket, int i) {
        String ttl = tcpPacket.get(i).substring(tcpPacket.get(i).indexOf("ttl ") + 4, tcpPacket.get(i).indexOf(", id "));
        //  System.out.println("\nTTL:"+ttl);
        return Integer.parseInt(ttl);
    }
}

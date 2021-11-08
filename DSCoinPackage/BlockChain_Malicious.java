package DSCoinPackage;

import HelperClasses.CRF;
import HelperClasses.MerkleTree;

public class BlockChain_Malicious {

  public int tr_count;
  public static final String start_string = "DSCoin";
  public TransactionBlock[] lastBlocksList;

  public static boolean checkTransactionBlock (TransactionBlock tB) {
    CRF newobj = new CRF(64);
    MerkleTree checkSum = new MerkleTree();
    if(!tB.dgst.startsWith("0000")) {return false;}
    if(tB.previous == null) {
      if(!tB.dgst.equals(newobj.Fn(start_string + "#" + tB.trsummary + "#" + tB.nonce)))
        return false;
    }
    else {
      if(!tB.dgst.equals(newobj.Fn(tB.previous.dgst + "#" + tB.trsummary + "#" + tB.nonce)))
        return false;
    }
    // dgst is verified
    checkSum.Build(tB.trarray);
    if(!tB.trsummary .equals(checkSum.rootnode.val) ) {return false;}
    // trsummary computation is checked
    for(int i = 0 ; i < tB.trarray.length; i++) {
      try{
      if( !tB.checkTransaction(tB.trarray[i]) ) {return false;}
      }
      catch(Exception e){

      }
    }
    // every transaction in trarray is checked
    return true;
   
   
 



  
  }

  public TransactionBlock FindLongestValidChain () {
    // if list has no elements it should return null
    int maxChainLength = 0;
    int l;
    int maxCLIndex = 0;
    TransactionBlock curr; // this is used for chain traversing
    TransactionBlock curr1; // this will be the last TB of the longest BC
    for(int i = 0; i < this.lastBlocksList.length; i++) {
      curr = lastBlocksList[i];
      l = 0;
      while(curr != null) {
        if(checkTransactionBlock(curr)) l++;
        else l = 0;
        curr = curr.previous;
      }
      if(l > maxChainLength) {
        maxChainLength = l;
        maxCLIndex = i;
      }
    }
    curr = lastBlocksList[maxCLIndex];
    curr1 = lastBlocksList[maxCLIndex];
    while(curr!=null){
       if(!checkTransactionBlock(curr)) {curr1 = curr;}
       curr = curr.previous;
    }
    return curr1.previous;
    
  
  

    
  }
  

  public void InsertBlock_Malicious (TransactionBlock newBlock) {
    

    int j =0;
    // for lastblocklist null, no need to find longest valid
    if(lastBlocksList == null){
      lastBlocksList = new TransactionBlock[1];
      lastBlocksList[0] = newBlock;
      lastBlocksList[0].previous = null;
      j = 0;
      return;
    }
    else if(lastBlocksList[0] == null){
      
      lastBlocksList = new TransactionBlock[1];
      lastBlocksList[0] = newBlock;
      lastBlocksList[0].previous = null;
      j = 0;
      int s = 1000000001;
      CRF obj = new CRF(64);
      while(true){
        String s1 = Integer.toString(s);
        String s2 = "";
        
          s2 = obj.Fn(start_string + "#" + lastBlocksList[0].trsummary + "#" + s1);
        
        
        boolean chk = true;
        for(int i = 0; i < 4; i++){
          if(s2.charAt(i) != '0'){
            chk = false;
          }
  
  
        }
        if(chk){
          lastBlocksList[0].dgst = s2;
          lastBlocksList[0].nonce = s1;
          break;
  
        }
        s++;
      }
      return;

    }
    else{
      // connecting block to the returned block of findlongestValid
      newBlock.previous = this.FindLongestValidChain();
     
      boolean check = false;
      int i =0;
    
      
      while(!check && i < lastBlocksList.length){
        if(newBlock.previous == lastBlocksList[i]){
          check = true;
          j = i;
        }
        i++;
      }
      // if check is true this means longest valid block is in lastblocklist and no need to increase leaf blocks just replace that one
      if(check){
        
        lastBlocksList[j] = newBlock;                
      }
      // else add a new block in lastblock list 
      else{
        // resizing lastblock list
        TransactionBlock[] arr = new TransactionBlock[lastBlocksList.length + 1];
        int i_6 = 0;
        for(int i_5 = 0; i_5 < lastBlocksList.length; i_5++){
          arr[i_5] = lastBlocksList[i_5];
          i_6++;
        }
        arr[i_6] = newBlock;
        lastBlocksList = arr;
        j = arr.length -1;

      }

    }
    CRF obj = new CRF(64);

    // computing dgst and nonce
    int s = 1000000001;
    while(true){
      String s1 = Integer.toString(s);
      String s2 = "";
      if(lastBlocksList[j].previous == null){
         s2 = obj.Fn(start_string + "#" + lastBlocksList[j].trsummary + "#" + s1);
      }
      else{
       s2 = obj.Fn(lastBlocksList[j].previous.dgst + "#" + lastBlocksList[j].trsummary + "#" + s1);
      }
      boolean chk = true;
      for(int i = 0; i < 4; i++){
        if(s2.charAt(i) != '0'){
          chk = false;
        }


      }
      if(chk){
        lastBlocksList[j].dgst = s2;
        lastBlocksList[j].nonce = s1;
        break;

      }
      s++;
    }


    return;
  }

      

      
    
    


  
}

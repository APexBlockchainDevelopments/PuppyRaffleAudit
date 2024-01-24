Denial of Service attack


## [M-#] Looping through players array to check for duplicates in `PuppyRaffle::enterRaffle` isa potential denial of service (DoS) attack, incrementing gas costs for future entrants.

**Description:** The `PuppyRaffle::enterRaffle` function loops through `players` array to check for duplicates. However the longer the `PuppyRaffle::players` array is, the more checks a new player will have to make. This means the gas cost forplayers who enter right when the raffle stats will be dramatically lower han those who enter later. Every additional address in the `players` array, is an additional check the loop will have to make.

```javascript
//@audit DoS Attack
        for (uint256 i = 0; i < players.length - 1; i++) {
            for (uint256 j = i + 1; j < players.length; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
```

**Impact:** The gas costs for raffle entrants will greatly increase as more players enter the raffle. Discouraging later users from entering,and causing a rush at the start of the raffle to be one ofthe first entrants in the queue.

An attack might make the `PuppyRaffle::entrants` array so big, that no one else enters, guarenteeing themselves the win.

**Proof of Concept:**

If we have 2 sets of 100 players enter, the gas costs will be as such:
-1st 100 players: ~6252048 gas
-2nd 100 players: ~18068138 gas

This is more than 3x times more expensive for the second 100 players.

<details>
<summary>PoC</summary>
Place the following test into `PuppyRaffleTest.t.sol` 

```javascript
    function test_denialOfService() public {
        vm.txGasPrice(1);

        //Let's enter 100 players

        uint256 playersNum = 100;
        address[] memory newPlayers = new address[](playersNum);
        for(uint256 i = 0; i<playersNum; i++){
            newPlayers[i] = address(i);
        }

        //see how much gas it costs
        uint256 gasStart = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * newPlayers.length}(newPlayers);
        uint256 gasEnd = gasleft();

        uint256 gasUsedFirst = (gasStart - gasEnd) * tx.gasprice;

        console.log("Gas cost of the first 100 players" , gasUsedFirst);

        //Second 100 players
        address[] memory newPlayersTwo = new address[](playersNum);
        for(uint256 i = 0; i<playersNum; i++){
            newPlayersTwo[i] = address(i + playersNum);
        }

        //see how much gas it costs
        uint256 gasStartSecond = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * newPlayersTwo.length}(newPlayersTwo);
        uint256 gasEndSecond = gasleft();

        uint256 gasUsedSecond = (gasStartSecond - gasEndSecond) * tx.gasprice;

        console.log("Gas cost of the second 100 players" , gasUsedSecond);

        assert(gasUsedFirst < gasEndSecond);
    }
```
</details>

**Recommended Mitigation:** There are a few recommendations. 

1. Consider allowing duplicates. Users can make new wallet addresses anyways, so a duplicate check prevent the same person from entering multiple times, only the same wallet address.
2. Consdering using a mapping to check for duplicates. This would allow constant time lookup of wehter a user has already entered.

```diff
+ uint256 public raffleID;
+ mapping (address => uint256) public usersToRaffleId;
.
.
function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        for (uint256 i = 0; i < newPlayers.length; i++) {
            players.push(newPlayers[i]);
+           usersToRaffleId[newPlayers[i]] = true;
        }
        
        // Check for duplicates
+       for (uint256 i = 0; i < newPlayers.length; i++){
+           require(usersToRaffleId[i] != raffleID, "PuppyRaffle: Already a participant");

-        for (uint256 i = 0; i < players.length - 1; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
-                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-            }
        }

        emit RaffleEnter(newPlayers);
    }
.
.
.

function selectWinner() external {
        //Existing code
+    raffleID = raffleID + 1;        
    }
```

Alterntively, you could use [OpenZeppelin's`EnumerableSet` library]
(htps://docs.oppenzeppelin.com/contracts/4.x/api/utils#EnumerableSet)/
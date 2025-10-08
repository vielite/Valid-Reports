## [Low-1] handleAgentTaxes() is vulnerable to silent failures
### Finding description and impact
The `handleAgentTaxes()` function fails to check the status of the external call to _swapForAsset() which returns bool allowing for silent failures.
```solidity
        revert TxHashExists(txhash);
            }
            taxHistory[txhash] = TaxHistory(agentId, amounts[i]);
            totalAmount += amounts[i];
            emit TaxCollected(txhash, agentId, amounts[i]);
        }
        agentAmounts.amountCollected += totalAmount;
        _swapForAsset(agentId, minOutput, maxSwapThreshold);
    }
```
`_swapForAssets()` returns important information which is ignored by the function after updating `agentAmounts.amountCollected`. The `swapForAssets()` returns (false,0) in multiple scenarios :

if `amountToSwap < minSwapThreshold`
if the swap transaction fails in the try-catch block
When successful, it returns (true, amounts[1]) with the actual amount received.

The vulnerability is serious because:

handleAgentTaxes updates the `agentAmounts.amountCollected` but relies on `_swapForAsset` to update `agentAmounts.amountSwapped`. If the swap fails, this update never happens.
Despite tax transactions being recorded and marked as processed in taxHistory, the actual swap to asset tokens might never occur, creating a significant inconsistencies between recorded and actual state.
Since no transaction will be reverted when the swap fails, the contract state will become inconsistent with accounting records.

### Recommended mitigation steps
Check the return value of `_swapForAsset()` for failures or return of (false,0)

### Links to affected code
AgentTax.sol#L168
AgentTax.sol#L187

https://code4rena.com/audits/2025-04-virtuals-protocol/submissions/F-222

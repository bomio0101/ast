import time

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score, classification_report
from sklearn.preprocessing import label_binarize
from torch_geometric.loader import TemporalDataLoader
from torch_geometric.nn import TGNMemory
from torch_geometric.nn.models.tgn import (
    IdentityMessage,
    LastAggregator,
    LastNeighborLoader,
)

from datasets import ToNDataset
from model.MGD import MGD
from utils.LOSS import Loss
from utils.MLP import MLPPredictor
from utils.funcs import *
from sklearn.metrics import f1_score

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

# data = ToNDataset()
# data = data.get()
data = torch.load("3D-IDS/data/CIC-ToN-IoT.pt")
data = data.to(device)
min_dst_idx, max_dst_idx = int(data.dst.min()), int(data.dst.max())
train_data, test_data, val_data = data.train_val_test_split(
    val_ratio=0.15, test_ratio=0.15)
train_loader = TemporalDataLoader(train_data, batch_size=200)
test_loader = TemporalDataLoader(test_data, batch_size=200)
val_loader = TemporalDataLoader(val_data, batch_size=200)
neighbor_loader = LastNeighborLoader(data.num_nodes, size=10, device=device)
memory_dim = time_dim = embedding_dim = 128
layer = 1
gind_params = {'num_layers': 1, 'alpha': 0.02, 'hidden_channels': 128, 'drop_input': True, 'dropout_imp': 0.5,
               'dropout_exp': 0.0, 'iter_nums': [36, 4], 'linear': True, 'double_linear': True, 'act_imp': 'tanh',
               'act_exp': 'elu', 'rescale': True, 'residual': True, 'norm': 'LayerNorm', 'final_reduce': None}

memory = TGNMemory(
    data.num_nodes,
    data.msg.size(-1),
    memory_dim,
    time_dim,
    message_module=IdentityMessage(data.msg.size(-1), memory_dim, time_dim),
    aggregator_module=LastAggregator(),
).to(device)

mgd = MGD(in_channels=embedding_dim, out_channels=embedding_dim, **gind_params).to(device)

bin_predictor = MLPPredictor(in_features=embedding_dim, out_classes=2).to(device)
mul_predictor = MLPPredictor(in_features=embedding_dim, out_classes=10).to(device)

optimizer = torch.optim.Adam(
    set(memory.parameters()) | set(mgd.parameters())
    | set(bin_predictor.parameters()) | set(mul_predictor.parameters()), lr=0.0001)
criterion = Loss(2, 10)
assoc = torch.empty(data.num_nodes, dtype=torch.long, device=device)


def train():
    memory.train()
    mgd.train()
    bin_predictor.train()
    mul_predictor.train()
    memory.reset_state()  # Start with a fresh memory.
    neighbor_loader.reset_state()  # Start with an empty graph.
    total_loss = 0
    for batch in train_loader:
        batch = batch.to(device)
        optimizer.zero_grad()
        src, dst, t, msg, label, attack = batch.src, batch.dst, batch.t, batch.msg, batch.label, batch.attack
        n_id = torch.cat([src, dst]).unique()
        n_id, edge_index, e_id = neighbor_loader(n_id)
        assoc[n_id] = torch.arange(n_id.size(0), device=device)
        z, last_update = memory(n_id)
        ed, m = nodeMap(torch.stack((src, dst), dim=0))
        ed = ed.to(device)
        norm_factor, ed = cal_norm(ed, num_nodes=len(z), self_loop=False)
        z = mgd(z, ed, norm_factor).to(device)
        # binary
        bin_out = bin_predictor(z[assoc[src]], z[assoc[dst]])
        mul_out = mul_predictor(z[assoc[src]], z[assoc[dst]])
        loss = criterion(bin_out,mul_out,label,attack,z)
        # multiple
        memory.update_state(src, dst, t, msg)
        neighbor_loader.insert(src, dst)
        loss.backward()
        optimizer.step()
        memory.detach()
        total_loss += float(loss) * batch.num_events
    return total_loss / train_data.num_events


@torch.no_grad()
def test(loader):
    memory.eval()
    mgd.eval()
    bin_predictor.eval()
    torch.manual_seed(12345)  # Ensure deterministic sampling across epochs.
    preds, trues = [], []
    for batch in loader:
        batch = batch.to(device)
        src, dst, t, msg, label, attack = batch.src, batch.dst, batch.t, batch.msg, batch.label, batch.attack
        n_id = torch.cat([src, dst]).unique()
        n_id, edge_index, e_id = neighbor_loader(n_id)
        assoc[n_id] = torch.arange(n_id.size(0), device=device)

        z, last_update = memory(n_id)
        ed, m = nodeMap(torch.stack((src, dst), dim=0))
        ed = ed.to(device)
        norm_factor, ed = cal_norm(ed, num_nodes=len(z), self_loop=False)
        z = mgd(z, ed, norm_factor).to(device)
        out = mul_predictor(z[assoc[src]], z[assoc[dst]]).argmax(1)
        y_pred = out.cpu()
        y_true = attack.cpu()
        preds += y_pred.tolist()
        trues += y_true.tolist()
        memory.update_state(src, dst, t, msg)
        neighbor_loader.insert(src, dst)
    preds = np.array(preds).flatten()
    trues = np.array(trues).flatten()
    f1ss = f1_score(trues,preds,average='micro')
    return f1ss


def main():
    for epoch in range(1, 6):
        loss = train()
        print(f'Epoch: {epoch:02d}, Loss: {loss:.4f}')
        st = time.time()
        test_f1 = test(test_loader)
        ft = time.time()
        dt = ft-st
        print(f'Test time for epoch {epoch:02d}: {dt}, avrage: {dt / 200}')
        print(f'Test F1: {test_f1:.4f}')


if __name__ == '__main__':
main()

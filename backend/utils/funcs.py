import torch
import torch.nn.functional as F
from torch_geometric.utils import to_undirected, degree
from torch_scatter import scatter_add


def nodeMap(edge_index, mode='encode', decode_dict=None):
    if mode == 'encode':
        src, dst = edge_index.tolist()
        nodeSet = sorted(list(set(src + dst)))
        assoc = list(range(0, len(nodeSet)))
        m = [dict(zip(nodeSet, assoc)), dict(zip(assoc, nodeSet))]
        src = [m[0][i] for i in src]
        dst = [m[0][i] for i in dst]
        edge_index = torch.stack((torch.tensor(src), torch.tensor(dst)), dim=0)
        return edge_index, m
    elif mode == 'decode':
        src, dst = edge_index.tolist()
        src = [decode_dict[i] for i in src]
        dst = [decode_dict[i] for i in dst]
        edge_index = torch.stack((torch.tensor(src), torch.tensor(dst)), dim=0)
        return edge_index
    else:
        print('Error mode.')


def get_act(act_type):
    act_type = act_type.lower()
    if act_type == 'identity':
        return torch.nn.Identity()
    if act_type == 'relu':
        return torch.nn.ReLU(inplace=True)
    elif act_type == 'elu':
        return torch.nn.ELU(inplace=True)
    elif act_type == 'tanh':
        return torch.nn.Tanh()
    else:
        raise NotImplementedError


def cal_norm(edge_index, num_nodes=None, self_loop=False, cut=False):
    # calculate normalization factors: (2*D)^{-1/2}
    if num_nodes is None:
        num_nodes = edge_index.max() + 1
    D = degree(edge_index[0], num_nodes)
    if self_loop:
        D = D + 1

    if cut:  # for symmetric adj
        D = torch.sqrt(1 / D)
        D[D == float("inf")] = 0.
        edge_index = to_undirected(edge_index, num_nodes=num_nodes)
        row, col = edge_index
        mask = row < col
        edge_index = edge_index[:, mask]
    else:
        D = torch.sqrt(1 / 2 / D)
        D[D == float("inf")] = 0.
    # D = Tensor([0.5] * num_nodes).to(device)
    if D.dim() == 1:
        D = D.unsqueeze(-1)
    return D, edge_index


@torch.enable_grad()
def regularize(z, x, reg_type, edge_index=None, norm_factor=None):
    z_reg = norm_factor * z

    if reg_type == 'Lap':  # Laplacian Regularization
        row, col = edge_index
        loss = scatter_add(((z_reg.index_select(0, row) - z_reg.index_select(0, col)) ** 2).sum(-1), col, dim=0,
                           dim_size=z.size(0))
        return loss.mean()

    elif reg_type == 'Dec':  # Feature Decorrelation
        zzt = torch.mm(z_reg.t(), z_reg)
        Dig = 1. / torch.sqrt(1e-8 + torch.diag(zzt, 0))
        z_new = torch.mm(z_reg, torch.diag(Dig))
        zzt = torch.mm(z_new.t(), z_new)
        zzt = zzt - torch.diag(torch.diag(zzt, 0))
        zzt = F.hardshrink(zzt, lambd=0.5)
        square_loss = F.mse_loss(zzt, torch.zeros_like(zzt))
        return square_loss

    else:
        raise NotImplementedError

// Implicit_Func.py
from utils.VariationalHidDropout import VariationalHidDropout
from utils.funcs import *
from utils.LayerNorm import LayerNorm

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

class Implicit_Func(torch.nn.Module):
    def __init__(self, hidden_channel, middle_channel, alpha, norm, dropout, act, double_linear, rescale):
        super().__init__()
        self.alpha = alpha
        self.W = torch.nn.Linear(hidden_channel, hidden_channel, bias=False)

        self.double_linear = double_linear
        if self.double_linear:
            self.U = torch.nn.Linear(hidden_channel, middle_channel)

        self.norm = eval(norm)(middle_channel)

        self.rescale = rescale

        self.act = get_act(act)

        self.drop = VariationalHidDropout(dropout)

    def _reset(self, z):
        self.drop.reset_mask(z)

    def forward(self, z, x, edge_index, norm_factor, batch):
        num_nodes = x.size(0)
        row, col = edge_index

        if self.rescale:
            degree = 1. / norm_factor
            degree[degree == float("inf")] = 0.
        else:
            degree = 1.
        degree = degree.to(device)
        # z.to(device)
        # x.to(device)
        if self.double_linear:
            # print(z)
            # print(x)
            # print(self.W(z))
            # print(self.U(x))
            WzUx = self.W(z) + degree * self.U(x)
        else:
            WzUx = self.W(z + degree * x)

        WzUx = norm_factor * WzUx
        WzUx = WzUx.index_select(0, row) - WzUx.index_select(0, col)

        if batch is not None:
            WzUx = self.norm(self.act(WzUx), batch.index_select(0, row))
        else:
            WzUx = self.norm(self.act(WzUx))

        new_z = scatter_add(WzUx * norm_factor[row], row, dim=0, dim_size=num_nodes)
        new_z -= scatter_add(WzUx * norm_factor[col], col, dim=0, dim_size=num_nodes)

        new_z = -F.linear(new_z, self.W.weight.t())

        z = self.alpha * self.drop(new_z) + (1 - self.alpha) * z

        return z


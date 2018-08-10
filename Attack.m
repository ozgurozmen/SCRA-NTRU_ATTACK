A = csvread("A.txt");
B = csvread("B.txt");
X = csvread("X.txt");



%A = randi(2,8192,8192) - 1;
%B = randi(2^32, 512,8192);


%% REAL ATTACK - FIRST STAGE (ECHELON)
tic

a = A(1:8161,:);
b = B(1:8161,:);
ab = [a b];

echelon = rref(ab);

toc

%% FIND THE SIGNATURE (add checking if ones(i) is a multiple of 256, in each iteration.
tic
target = A(8162,:);

ones = find(target);
signature = echelon(ones(1),:);
for i = 2:32
   signature = signature + echelon(ones(i)-i+2,:);
end

check = isequal(signature(8193:8704), B(8162,:));

toc
%% RANDOM CALC
probCheck = sum(A);
%[row col v] = find(A);
k = find(~probCheck);
%%
bt = transpose(B);
sk = bt/A;
tic
toc
%%
tic
R = rref(a);
toc

%%
bcheck = A*X;
check = eq(bcheck,B);
check2 = isequal(bcheck,B);

%%
[asub, idx] = licols(a);
%bsub = b(idx,:);


function [Xsub,idx]=licols(X,tol)
%Extract a linearly independent set of columns of a given matrix X
%
%    [Xsub,idx]=licols(X)
%
%in:
%
%  X: The given input matrix
%  tol: A rank estimation tolerance. Default=1e-10
%
%out:
%
% Xsub: The extracted columns of X
% idx:  The indices (into X) of the extracted columns
     if ~nnz(X) %X has no non-zeros and hence no independent columns
         Xsub=[]; idx=[];
         return
     end
     if nargin<2, tol=1e-10; end
       [Q, R, E] = qr(X,0); 
       if ~isvector(R)
        diagr = abs(diag(R));
       else
        diagr = R(1);   
       end
       %Rank estimation
       r = find(diagr >= tol*diagr(1), 1, 'last'); %rank estimation
       idx=sort(E(1:r));
       Xsub=X(:,idx);   
       
end
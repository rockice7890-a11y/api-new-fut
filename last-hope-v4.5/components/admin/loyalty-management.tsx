'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Switch } from '@/components/ui/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

interface LoyaltyTier {
  name: string
  minPoints: number
  maxPoints: number
  benefits: string[]
  multiplier: number
}

interface LoyaltyPoint {
  id: string
  userId: string
  user: {
    firstName: string
    lastName: string
    email: string
  }
  points: number
  tier: string
  totalEarned: number
  totalRedeemed: number
  updatedAt: string
}

interface LoyaltyTransaction {
  id: string
  userId: string
  user: {
    firstName: string
    lastName: string
    email: string
  }
  action: string
  points: number
  description: string
  referenceId?: string
  expiresAt?: string
  createdAt: string
}

export default function LoyaltyManagement() {
  const [loyaltyPoints, setLoyaltyPoints] = useState<LoyaltyPoint[]>([])
  const [transactions, setTransactions] = useState<LoyaltyTransaction[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState('overview')

  // Show points dialog
  const [showPointsDialog, setShowPointsDialog] = useState(false)
  const [selectedUser, setSelectedUser] = useState<LoyaltyPoint | null>(null)
  const [pointsAction, setPointsAction] = useState('add')
  const [pointsAmount, setPointsAmount] = useState('')
  const [pointsReason, setPointsReason] = useState('')

  // Loyalty tiers configuration
  const loyaltyTiers: LoyaltyTier[] = [
    {
      name: 'BRONZE',
      minPoints: 0,
      maxPoints: 999,
      benefits: ['خصم 5%', 'نقاط مضاعفة في المسابقات'],
      multiplier: 1.0
    },
    {
      name: 'SILVER',
      minPoints: 1000,
      maxPoints: 4999,
      benefits: ['خصم 10%', 'ترقية مجانية للغرفة', 'خدمة سبا مجانية'],
      multiplier: 1.5
    },
    {
      name: 'GOLD',
      minPoints: 5000,
      maxPoints: 14999,
      benefits: ['خصم 15%', 'ترقية مجانية للغرفة', 'خدمة سبا مجانية', 'إفطار مجاني'],
      multiplier: 2.0
    },
    {
      name: 'PLATINUM',
      minPoints: 15000,
      maxPoints: 999999,
      benefits: ['خصم 20%', 'جميع المميزات', 'خدمة شخصية', 'إقامة مجانية ليلة واحدة'],
      multiplier: 3.0
    }
  ]

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    try {
      setLoading(true)

      // Fetch loyalty points
      const loyaltyResponse = await fetch('/api/loyalty/points')
      if (loyaltyResponse.ok) {
        const loyaltyData = await loyaltyResponse.json()
        if (loyaltyData.status === 'success') {
          setLoyaltyPoints(loyaltyData.data)
        }
      }

      // Fetch loyalty transactions (would need to create this endpoint)
      const transactionsResponse = await fetch('/api/loyalty/transactions')
      if (transactionsResponse.ok) {
        const transactionsData = await transactionsResponse.json()
        if (transactionsData.status === 'success') {
          setTransactions(transactionsData.data)
        }
      }

      setError(null)
    } catch (error: any) {
      console.error('Error fetching loyalty data:', error)
      setError(error.message)
    } finally {
      setLoading(false)
    }
  }

  const handlePointsAction = async () => {
    try {
      const response = await fetch('/api/loyalty/points/adjust', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId: selectedUser?.userId,
          points: pointsAction === 'add' ? parseInt(pointsAmount) : -parseInt(pointsAmount),
          reason: pointsReason,
          action: pointsAction
        })
      })

      if (response.ok) {
        await fetchData()
        setShowPointsDialog(false)
        setPointsAmount('')
        setPointsReason('')
        setSelectedUser(null)
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const getTierInfo = (points: number) => {
    return loyaltyTiers.find(tier => points >= tier.minPoints && points <= tier.maxPoints) || loyaltyTiers[0]
  }

  const getTierBadgeVariant = (tier: string) => {
    switch (tier) {
      case 'BRONZE': return 'secondary'
      case 'SILVER': return 'default'
      case 'GOLD': return 'destructive'
      case 'PLATINUM': return 'default'
      default: return 'secondary'
    }
  }

  const totalPoints = loyaltyPoints.reduce((sum, user) => sum + user.points, 0)
  const averagePoints = loyaltyPoints.length > 0 ? Math.round(totalPoints / loyaltyPoints.length) : 0

  const tierDistribution = loyaltyTiers.map(tier => ({
    ...tier,
    count: loyaltyPoints.filter(user => 
      user.points >= tier.minPoints && user.points <= tier.maxPoints
    ).length
  }))

  if (loading) {
    return <div className="flex items-center justify-center p-8">جاري التحميل...</div>
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold">إدارة برنامج الولاء</h2>
      </div>

      {error && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
          <p className="text-red-800 font-medium">خطأ: {error}</p>
        </div>
      )}

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview">نظرة عامة</TabsTrigger>
          <TabsTrigger value="members">الأعضاء والنقاط</TabsTrigger>
          <TabsTrigger value="transactions">المعاملات</TabsTrigger>
          <TabsTrigger value="tiers">فئات الولاء</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>إجمالي أعضاء الولاء</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{loyaltyPoints.length}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>إجمالي النقاط الموزعة</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{totalPoints.toLocaleString()}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>متوسط النقاط لكل عضو</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{averagePoints}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>النقاط المستبدلة</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">
                  {loyaltyPoints.reduce((sum, user) => sum + user.totalRedeemed, 0).toLocaleString()}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Tier Distribution */}
          <Card>
            <CardHeader>
              <CardTitle>توزيع الأعضاء حسب الفئات</CardTitle>
              <CardDescription>عدد الأعضاء في كل فئة من فئات الولاء</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {tierDistribution.map((tier) => (
                  <div key={tier.name} className="flex items-center justify-between p-4 border rounded-lg">
                    <div className="flex items-center space-x-4">
                      <Badge variant={getTierBadgeVariant(tier.name)}>{tier.name}</Badge>
                      <div>
                        <p className="font-medium">{tier.count} عضو</p>
                        <p className="text-sm text-muted-foreground">
                          {tier.minPoints} - {tier.maxPoints === 999999 ? '∞' : tier.maxPoints} نقطة
                        </p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-sm text-muted-foreground">مضاعف النقاط: x{tier.multiplier}</p>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="members" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>إدارة نقاط الأعضاء</CardTitle>
              <CardDescription>عرض وإدارة نقاط الولاء لجميع الأعضاء</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>العضو</TableHead>
                    <TableHead>البريد الإلكتروني</TableHead>
                    <TableHead>النقاط الحالية</TableHead>
                    <TableHead>الفئة</TableHead>
                    <TableHead>إجمالي المكتسب</TableHead>
                    <TableHead>إجمالي المستبدل</TableHead>
                    <TableHead>آخر تحديث</TableHead>
                    <TableHead>الإجراءات</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {loyaltyPoints.map((user) => {
                    const tier = getTierInfo(user.points)
                    return (
                      <TableRow key={user.id}>
                        <TableCell className="font-medium">
                          {user.user.firstName} {user.user.lastName}
                        </TableCell>
                        <TableCell>{user.user.email}</TableCell>
                        <TableCell>
                          <span className="font-bold text-lg">{user.points.toLocaleString()}</span>
                        </TableCell>
                        <TableCell>
                          <Badge variant={getTierBadgeVariant(user.tier)}>{user.tier}</Badge>
                        </TableCell>
                        <TableCell>{user.totalEarned.toLocaleString()}</TableCell>
                        <TableCell>{user.totalRedeemed.toLocaleString()}</TableCell>
                        <TableCell>{new Date(user.updatedAt).toLocaleDateString('ar')}</TableCell>
                        <TableCell>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              setSelectedUser(user)
                              setShowPointsDialog(true)
                            }}
                          >
                            إدارة النقاط
                          </Button>
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          <Dialog open={showPointsDialog} onOpenChange={setShowPointsDialog}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>إدارة نقاط الولاء</DialogTitle>
                <DialogDescription>
                  {selectedUser && `${selectedUser.user.firstName} ${selectedUser.user.lastName} - النقاط الحالية: ${selectedUser.points}`}
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-4 py-4">
                <div className="space-y-2">
                  <Label>الإجراء</Label>
                  <Select value={pointsAction} onValueChange={setPointsAction}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="add">إضافة نقاط</SelectItem>
                      <SelectItem value="subtract">خصم نقاط</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>عدد النقاط</Label>
                  <Input
                    type="number"
                    value={pointsAmount}
                    onChange={(e) => setPointsAmount(e.target.value)}
                    placeholder="أدخل عدد النقاط"
                  />
                </div>
                <div className="space-y-2">
                  <Label>السبب</Label>
                  <Textarea
                    value={pointsReason}
                    onChange={(e) => setPointsReason(e.target.value)}
                    placeholder="سبب إضافة أو خصم النقاط..."
                    rows={3}
                  />
                </div>
              </div>
              <div className="flex justify-end space-x-2">
                <Button variant="outline" onClick={() => setShowPointsDialog(false)}>
                  إلغاء
                </Button>
                <Button onClick={handlePointsAction}>
                  تنفيذ الإجراء
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </TabsContent>

        <TabsContent value="transactions" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>سجل معاملات الولاء</CardTitle>
              <CardDescription>جميع معاملات النقاط والأحداث</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>العضو</TableHead>
                    <TableHead>نوع الإجراء</TableHead>
                    <TableHead>النقاط</TableHead>
                    <TableHead>الوصف</TableHead>
                    <TableHead>الرقم المرجعي</TableHead>
                    <TableHead>تاريخ انتهاء الصلاحية</TableHead>
                    <TableHead>التاريخ</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {transactions.map((transaction) => (
                    <TableRow key={transaction.id}>
                      <TableCell className="font-medium">
                        {transaction.user.firstName} {transaction.user.lastName}
                      </TableCell>
                      <TableCell>
                        <Badge variant={transaction.points > 0 ? "default" : "destructive"}>
                          {transaction.action}
                        </Badge>
                      </TableCell>
                      <TableCell className={transaction.points > 0 ? "text-green-600" : "text-red-600"}>
                        {transaction.points > 0 ? '+' : ''}{transaction.points}
                      </TableCell>
                      <TableCell>{transaction.description}</TableCell>
                      <TableCell className="text-muted-foreground">{transaction.referenceId || '-'}</TableCell>
                      <TableCell className="text-muted-foreground">
                        {transaction.expiresAt ? new Date(transaction.expiresAt).toLocaleDateString('ar') : '-'}
                      </TableCell>
                      <TableCell>{new Date(transaction.createdAt).toLocaleDateString('ar')}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="tiers" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>إعداد فئات الولاء</CardTitle>
              <CardDescription>إدارة مستويات وفوائد برنامج الولاء</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                {tierDistribution.map((tier, index) => (
                  <Card key={tier.name} className="p-6">
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center space-x-4">
                        <Badge variant={getTierBadgeVariant(tier.name)} className="text-lg px-3 py-1">
                          {tier.name}
                        </Badge>
                        <div>
                          <h3 className="text-lg font-semibold">
                            {tier.minPoints.toLocaleString()} - {tier.maxPoints === 999999 ? '∞' : tier.maxPoints.toLocaleString()} نقطة
                          </h3>
                          <p className="text-sm text-muted-foreground">مضاعف النقاط: x{tier.multiplier}</p>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-2xl font-bold">{tier.count} عضو</p>
                        <p className="text-sm text-muted-foreground">أعضاء في هذه الفئة</p>
                      </div>
                    </div>
                    <div>
                      <h4 className="font-medium mb-2">الفوائد:</h4>
                      <ul className="space-y-1">
                        {tier.benefits.map((benefit, benefitIndex) => (
                          <li key={benefitIndex} className="text-sm flex items-center">
                            <span className="w-2 h-2 bg-primary rounded-full mr-2"></span>
                            {benefit}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </Card>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}